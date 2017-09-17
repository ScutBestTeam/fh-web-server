package com.fh.interceptor;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;
import com.fh.entity.system.User;
import com.fh.util.Const;
import com.fh.util.Jurisdiction;
import com.fh.util.Logger;

import net.sf.json.JSONObject;

/**
 * 
 * 类名称：登录过滤，权限验证 类描述：
 * 
 * @author FH qq313596790[青苔] 作者单位： 联系方式： 创建时间：2015年11月2日
 * @version 1.6
 */
public class AppLoginHandlerInterceptor extends HandlerInterceptorAdapter {
	protected Logger logger = Logger.getLogger(this.getClass());

	@Override
	public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
			throws Exception {
		// TODO Auto-generated method stub
		String path = request.getServletPath();
		Map map = new HashMap();
		if (path.matches(Const.App_NO_INTERCEPTOR_PATH)) {
			return true;
		} else {
			if (SecurityUtils.getSubject() == null) {
				map.put("result", "401");
				responseOutWithJson(response, map);
				return false;
			} else
				return true;
		}

	}

	/**
	 * 以JSON格式输出
	 * 
	 * @param response
	 */
	protected void responseOutWithJson(HttpServletResponse response, Object responseObject) {
		// 将实体对象转换为JSON Object转换
		JSONObject responseJSONObject = JSONObject.fromObject(responseObject);
		response.setCharacterEncoding("UTF-8");
		response.setContentType("application/json; charset=utf-8");
		PrintWriter out = null;
		try {
			out = response.getWriter();
			out.append(responseJSONObject.toString());
			logger.debug("返回是\n");
			logger.debug(responseJSONObject.toString());
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			if (out != null) {
				out.close();
			}
		}
	}

}
