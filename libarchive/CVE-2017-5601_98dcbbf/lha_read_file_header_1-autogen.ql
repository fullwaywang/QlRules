/**
 * @name libarchive-98dcbbf0bf4854bf987557e55e55fff7abbf3ea9-lha_read_file_header_1
 * @id cpp/libarchive/98dcbbf0bf4854bf987557e55e55fff7abbf3ea9/lha-read-file-header-1
 * @description libarchive-98dcbbf0bf4854bf987557e55e55fff7abbf3ea9-libarchive/archive_read_support_format_lha.c-lha_read_file_header_1 CVE-2017-5601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlha_875, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="compsize"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlha_875
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(GotoStmt).toString() = "goto ..."
		and target_0.getThen().(GotoStmt).getName() ="invalid"
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlha_875, ExprStmt target_1) {
		target_1.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="compsize"
		and target_1.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vlha_875
		and target_1.getExpr().(AssignSubExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="2"
}

from Function func, Parameter vlha_875, ExprStmt target_1
where
not func_0(vlha_875, target_1, func)
and func_1(vlha_875, target_1)
and vlha_875.getType().hasName("lha *")
and vlha_875.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
