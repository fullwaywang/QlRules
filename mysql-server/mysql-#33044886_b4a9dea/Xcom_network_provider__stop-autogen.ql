/**
 * @name mysql-server-b4a9deaa3dd3c901b70f604b596a82c4309e3054-Xcom_network_provider__stop
 * @id cpp/mysql-server/b4a9deaa3dd3c901b70f604b596a82c4309e3054/xcomnetworkproviderstop
 * @description mysql-server-b4a9deaa3dd3c901b70f604b596a82c4309e3054-plugin/group_replication/libmysqlgcs/src/bindings/xcom/xcom/network/xcom_network_provider.cc-Xcom_network_provider__stop mysql-#33044886
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(IfStmt target_1, Function func, ExprStmt target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		obj_0.getTarget().hasName("reset_new_connection")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and target_1.getLocation().isBefore(target_0.getLocation())
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, IfStmt target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getCondition() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_network_provider_tcp_server"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getTarget().hasName("joinable")
	)
	and exists(ExprStmt obj_2 | obj_2=target_1.getThen() |
		exists(FunctionCall obj_3 | obj_3=obj_2.getExpr() |
			exists(PointerFieldAccess obj_4 | obj_4=obj_3.getQualifier() |
				obj_4.getTarget().getName()="m_network_provider_tcp_server"
				and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
			)
			and obj_3.getTarget().hasName("join")
		)
	)
	and target_1.getEnclosingFunction() = func
}

from Function func, ExprStmt target_0, IfStmt target_1
where
func_0(target_1, func, target_0)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
