package com.fh.controller.app.appuser;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Resource;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fh.controller.base.BaseController;
import com.fh.entity.system.Role;
import com.fh.entity.system.User;
import com.fh.service.system.appuser.AppuserManager;
import com.fh.service.system.role.RoleManager;
import com.fh.util.AppUtil;
import com.fh.util.Const;
import com.fh.util.DateUtil;
import com.fh.util.Jurisdiction;
import com.fh.util.PageData;
import com.fh.util.Tools;

/**
 * @author FH Q313596790 会员-接口类 相关参数协议： 00 请求失败 01 请求成功 02 返回空值 03 请求协议参数不完整 04
 *         用户名或密码错误 05 FKEY验证失败
 */
@Controller
@RequestMapping(value = "/appuser")
public class IntAppuserController extends BaseController {

	@Resource(name = "appuserService")
	private AppuserManager appuserService;
	@Resource(name = "roleService")
	private RoleManager roleService;

	/**
	 * 根据用户名获取会员信息
	 * 
	 * @return
	 */
	@RequestMapping(value = "/getAppuserByUm")
	@ResponseBody
	public Object getAppuserByUsernmae() {
		logBefore(logger, "根据用户名获取会员信息");
		Map<String, Object> map = new HashMap<String, Object>();
		PageData pd = new PageData();
		pd = this.getPageData();
		String result = "00";
		try {
			// if(Tools.checkKey("USERNAME", pd.getString("FKEY"))){
			// //检验请求key值是否合法
			if (AppUtil.checkParam("getAppuserByUsernmae", pd)) { // 检查参数
				pd = appuserService.findByUsername(pd);
				map.put("pd", pd);
				result = (null == pd) ? "02" : "01";
			} else {
				result = "03";
			}
			// }
			// else{
			// result = "05";
			// }
		} catch (Exception e) {
			logger.error(e.toString(), e);
		} finally {
			map.put("result", result);
			logAfter(logger);
		}
		return AppUtil.returnObject(new PageData(), map);
	}

	/**
	 * @param USERNAME
	 * @param PASSWORD
	 * @return
	 * @throws Exception
	 */
	@RequestMapping(value = "/login")
	@ResponseBody
	public Object login() throws Exception {
		Map map = new HashMap();
		boolean success = false;
		PageData pd = new PageData();
		pd = this.getPageData();
		String errInfo = "";
		String USERNAME = pd.getString("USERNAME"); // 登录过来的用户名
		String PASSWORD = pd.getString("PASSWORD"); // 登录过来的密码
		Session session = Jurisdiction.getSession();
		if (USERNAME != null && PASSWORD != null) {
			// 判断登录验证码
			String passwd = new SimpleHash("SHA-1", USERNAME, PASSWORD).toString(); // 密码加密

			pd = appuserService.findByUsername(pd); // 根据用户名去读取用户信息
			if (pd != null && pd.getString("STATUS") != null && pd.getString("STATUS").equals("0"))
				errInfo = "账号被冻结";
			else {
				if (pd != null && pd.getString("PASSWORD") != null && pd.getString("PASSWORD").equals(passwd)) {
					pd.put("LAST_LOGIN", DateUtil.getTime().toString());
					appuserService.updateLastLogin(pd);
					User user = new User();
					user.setUSER_ID(pd.getString("USER_ID"));
					user.setUSERNAME(pd.getString("USERNAME"));
					user.setPASSWORD(pd.getString("PASSWORD"));
					user.setNAME(pd.getString("NAME"));
					user.setRIGHTS(pd.getString("RIGHTS"));
					user.setROLE_ID(pd.getString("ROLE_ID"));
					user.setLAST_LOGIN(pd.getString("LAST_LOGIN"));
					user.setIP(pd.getString("IP"));
					user.setSTATUS(pd.getString("STATUS"));
					session.setAttribute(Const.SESSION_USER, user); // 把用户信息放session中
					session.removeAttribute(Const.SESSION_SECURITY_CODE); // 清除登录验证码的session
					// shiro加入身份验证
					Subject subject = SecurityUtils.getSubject();
					UsernamePasswordToken token = new UsernamePasswordToken(USERNAME, PASSWORD);
					try {
						subject.login(token);
						success = true;
					} catch (AuthenticationException e) {
						errInfo = "身份验证失败！";
					}
				} else {
					errInfo = "登录系统密码或用户名错误"; // 用户名或密码有误
					logBefore(logger, USERNAME + "登录系统密码或用户名错误");
				}
			}
			if (Tools.isEmpty(errInfo)) {
				errInfo = "success"; // 验证成功
				logBefore(logger, USERNAME + "登录系统");
			}
		} else {
			logger.info("账号为" + USERNAME);
			logger.info("密码为" + PASSWORD);
			errInfo = "账号或密码为空";
		}
		map.put("msg", errInfo);
		map.put("success", success);
		return AppUtil.returnObject(new PageData(), map);
	}

	/**
	 * 系统用户注册接口 00 请求失败 01 请求成功 02 返回空值 03
	 * 请求协议参数不完整(PHONE,EMAIL,USERNAME,NAME,PASSWORD) 04 用户名或密码错误 06验证码错误
	 * 
	 * @return
	 * @throws Exception
	 */
	@RequestMapping(value = "/register")
	@ResponseBody
	public Object registerSysUser() throws Exception {
		logBefore(logger, "app用户注册接口");
		Map<String, Object> map = new HashMap<String, Object>();
		PageData pd = new PageData();
		pd = this.getPageData();
		String result = "00";
		pd.put("ROLE_ID", "2");
		String roleID="";
		List<Role> roleList = roleService.listAllRolesByPId(pd);
		for (Role role : roleList) {
			if (role.getROLE_NAME().equals("初级会员"))
				roleID = role.getROLE_ID();
		}
		try {

			if (AppUtil.checkParam("getAppuserByUsername", pd)) { // 检查参数

				Session session = Jurisdiction.getSession();
				String permitCode = (String) session.getAttribute(Const.SESSION_SECURITY_PERMITTED); // 获取session中的验证码
				if (Tools.notEmpty(permitCode) && permitCode.equalsIgnoreCase("permitted")) { // 判断登录验证码
					pd.put("USER_ID", this.get32UUID()); // ID 主键
					pd.put("ROLE_ID", roleID); // 角色ID
					pd.put("NUMBER", ""); // 编号
					pd.put("BZ", "注册用户"); // 备注
					pd.put("LAST_LOGIN", ""); // 最后登录时间
					pd.put("IP", ""); // IP
					pd.put("STATUS", "1"); // 状态
					pd.put("SKIN", "default");
					pd.put("RIGHTS", "");
					pd.put("PASSWORD",
							new SimpleHash("SHA-1", pd.getString("USERNAME"), pd.getString("PASSWORD")).toString()); // 密码加密
					if (null == appuserService.findByUsername(pd)) { // 判断用户名是否存在
						appuserService.saveU(pd);
						result = "01";// 执行保存
					} else {
						result = "04"; // 用户名已存在
					}
				} else {
					result = "06"; // 验证码错误
				}
			} else {
				result = "03";
			}

		} catch (Exception e) {
			logger.error(e.toString(), e);
		} finally {
			map.put("result", result);
			logAfter(logger);
		}
		return AppUtil.returnObject(new PageData(), map);
	}
	
	/**注销登陆
	 * @return
	 * @throws Exception
	 */
	@RequestMapping(value = "/logout")
	@ResponseBody
	public Object logout() throws Exception {
		Map<String, Object> map = new HashMap<String, Object>();
		try{
		Subject subject = SecurityUtils.getSubject();
		logger.info(subject.getPrincipal().toString()+"注销登陆开始");
		subject.logout();
		logger.info("注销登陆成功");
		map.put("result", true);
		}
		catch(Exception e){
			e.printStackTrace();
			logger.warn("注销失败");
			map.put("result",false);
			return AppUtil.returnObject(new PageData(), map);
		}
		return AppUtil.returnObject(new PageData(), map);
	}
}
