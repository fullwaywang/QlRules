/**
 * @name httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-add_pass
 * @id cpp/httpd/a962ba73047b5478d702c8ad09fd1a167e1d3736/add-pass
 * @description httpd-a962ba73047b5478d702c8ad09fd1a167e1d3736-modules/proxy/mod_proxy.c-add_pass CVE-2021-44224
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcmd_2001, ExprStmt target_3, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="pool"
		and target_0.getQualifier().(VariableAccess).getTarget()=vcmd_2001
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Variable vr_2009, Parameter vcmd_2001, EqualityOperation target_4, LogicalAndExpr target_5, ExprStmt target_6, ExprStmt target_3, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const char *")
		and target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ap_proxy_de_socketfy")
		and target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="temp_pool"
		and target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2001
		and target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr_2009
		and target_1.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(StringLiteral).getValue()="ProxyPass|ProxyPassMatch uses an invalid \"unix:\" URL"
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_1)
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(NotExpr).getOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vcmd_2001, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="regex"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("proxy_alias *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ap_pregcomp")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2001
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("char *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_4(Variable vr_2009, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vr_2009
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Variable vr_2009, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_2009
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="33"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vr_2009
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
}

predicate func_6(Variable vr_2009, Parameter vcmd_2001, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="real"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("proxy_alias *")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("apr_pstrdup")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2001
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("ap_proxy_de_socketfy")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pool"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcmd_2001
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr_2009
}

from Function func, Variable vr_2009, Parameter vcmd_2001, PointerFieldAccess target_0, ExprStmt target_3, EqualityOperation target_4, LogicalAndExpr target_5, ExprStmt target_6
where
func_0(vcmd_2001, target_3, target_0)
and not func_1(vr_2009, vcmd_2001, target_4, target_5, target_6, target_3, func)
and func_3(vcmd_2001, target_3)
and func_4(vr_2009, target_4)
and func_5(vr_2009, target_5)
and func_6(vr_2009, vcmd_2001, target_6)
and vr_2009.getType().hasName("char *")
and vcmd_2001.getType().hasName("cmd_parms *")
and vr_2009.(LocalVariable).getFunction() = func
and vcmd_2001.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
