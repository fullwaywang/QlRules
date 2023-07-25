/**
 * @name httpd-d4901cb32133bc0e59ad193a29d1665597080d67-ap_proxy_pre_request
 * @id cpp/httpd/d4901cb32133bc0e59ad193a29d1665597080d67/ap-proxy-pre-request
 * @description httpd-d4901cb32133bc0e59ad193a29d1665597080d67-modules/proxy/proxy_util.c-ap_proxy_pre_request CVE-2021-40438
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(PointerDereferenceExpr target_6, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_0.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="500"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(PointerFieldAccess target_7, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_1.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="500"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Parameter vr_2309, Parameter vurl_2310, FunctionCall target_2) {
		target_2.getTarget().hasName("fix_uds_filename")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vr_2309
		and target_2.getArgument(1).(VariableAccess).getTarget()=vurl_2310
}

predicate func_3(Parameter vr_2309, Parameter vurl_2310, FunctionCall target_3) {
		target_3.getTarget().hasName("fix_uds_filename")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vr_2309
		and target_3.getArgument(1).(VariableAccess).getTarget()=vurl_2310
}

predicate func_4(PointerDereferenceExpr target_6, Function func, ExprStmt target_4) {
		target_4.getExpr() instanceof FunctionCall
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_4.getEnclosingFunction() = func
}

predicate func_5(PointerFieldAccess target_7, Function func, ExprStmt target_5) {
		target_5.getExpr() instanceof FunctionCall
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_7
		and target_5.getEnclosingFunction() = func
}

predicate func_6(PointerDereferenceExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget().getType().hasName("proxy_worker **")
}

predicate func_7(PointerFieldAccess target_7) {
		target_7.getTarget().getName()="reverse"
		and target_7.getQualifier().(VariableAccess).getTarget().getType().hasName("proxy_server_conf *")
}

from Function func, Parameter vr_2309, Parameter vurl_2310, FunctionCall target_2, FunctionCall target_3, ExprStmt target_4, ExprStmt target_5, PointerDereferenceExpr target_6, PointerFieldAccess target_7
where
not func_0(target_6, func)
and not func_1(target_7, func)
and func_2(vr_2309, vurl_2310, target_2)
and func_3(vr_2309, vurl_2310, target_3)
and func_4(target_6, func, target_4)
and func_5(target_7, func, target_5)
and func_6(target_6)
and func_7(target_7)
and vr_2309.getType().hasName("request_rec *")
and vurl_2310.getType().hasName("char **")
and vr_2309.getFunction() = func
and vurl_2310.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
