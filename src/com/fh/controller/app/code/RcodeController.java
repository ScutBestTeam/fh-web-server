package com.fh.controller.app.code;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.font.FontRenderContext;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.imageio.ImageIO;

import org.apache.shiro.session.Session;
import org.slf4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fh.controller.base.BaseController;
import com.fh.util.AppUtil;
import com.fh.util.Const;
import com.fh.util.Jurisdiction;
import com.fh.util.PageData;
import com.fh.util.SmsUtil;

/**
 *  
 * 
 * @author hts
 * @version date：2017年7月22日 下午4:03:17 
 * 
 */
@Controller
@RequestMapping(value = "/appCode")
public class RcodeController extends BaseController {
	
	/**
	 * 手机验证码发送
	 * 
	 * @return
	 */
	@RequestMapping("")
	@ResponseBody
	public Object telRcode() {
		String code = "";
		for (int i = 0; i < 4; i++) {
			code += randomChar();
		}
		String sendmsg = "您的验证码是：" + code + "。请不要把验证码泄露给其他人。";
		Map<String, Object> map = new HashMap<String, Object>();
		PageData pd = new PageData();
		pd = this.getPageData();
		Session session = Jurisdiction.getSession();
		session.setAttribute(Const.SESSION_SECURITY_CODE, code);
		String mobile = pd.getString("PHONE");
//     	SmsUtil.sendSms2(mobile, sendmsg);
		logger.info(code);
		
		return AppUtil.returnObject(new PageData(), map);
	}

	/**
	 * 2:没有按手机发送验证码按钮
	 * 1：成功
	 * 0：验证码输入错误
	 * @return
	 */
	@RequestMapping("/checkRcode")
	@ResponseBody
	public Object checkRcode() {
		Map<String, Object> map = new HashMap<String, Object>();
		PageData pd = new PageData();
		pd = this.getPageData();
		Session session = Jurisdiction.getSession();
		String sessionCode = (String) session.getAttribute(Const.SESSION_SECURITY_CODE); // 获取session中的验证码
		if(sessionCode==null) {
			
			map.put("result", "2");
		}
		else{
		String rcode = pd.getString("RCODE");
		if (sessionCode.equals(rcode)) {
			map.put("result", "1");
			session.setAttribute(Const.SESSION_SECURITY_PERMITTED,"permitted");
		} else
			map.put("result", "0");
		}
		return AppUtil.returnObject(new PageData(), map);
	
		}

	private char randomChar() {
		Random r = new Random();
		String s = "0123456789";
		return s.charAt(r.nextInt(s.length()));
	}

}
