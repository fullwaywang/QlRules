/**
 * @name httpd-a0521d289ae14e4ac004811dc1ef91b3e118a2f6-ap_proxy_get_worker_ex
 * @id cpp/httpd/a0521d289ae14e4ac004811dc1ef91b3e118a2f6/ap-proxy-get-worker-ex
 * @description httpd-a0521d289ae14e4ac004811dc1ef91b3e118a2f6-modules/proxy/proxy_util.c-ap_proxy_get_worker_ex CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmask_1728, NotExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vmask_1728
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="8"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0)
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vp_1724, Parameter vurl_1727, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vurl_1727
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ap_proxy_de_socketfy")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_1724
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vurl_1727
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vurl_1727, Function func, IfStmt target_2) {
		target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vurl_1727
		and target_2.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vmask_1728, NotExpr target_3) {
		target_3.getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vmask_1728
		and target_3.getOperand().(BitwiseAndExpr).getRightOperand().(BitwiseOrExpr).getValue()="3"
}

from Function func, Parameter vp_1724, Parameter vurl_1727, Parameter vmask_1728, ExprStmt target_1, IfStmt target_2, NotExpr target_3
where
not func_0(vmask_1728, target_3, func)
and func_1(vp_1724, vurl_1727, func, target_1)
and func_2(vurl_1727, func, target_2)
and func_3(vmask_1728, target_3)
and vp_1724.getType().hasName("apr_pool_t *")
and vurl_1727.getType().hasName("const char *")
and vmask_1728.getType().hasName("unsigned int")
and vp_1724.getFunction() = func
and vurl_1727.getFunction() = func
and vmask_1728.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
