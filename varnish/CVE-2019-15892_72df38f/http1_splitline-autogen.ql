/**
 * @name varnish-72df38fa8bfc0f5ca4a75d3e32657e8e590d85ab-http1_splitline
 * @id cpp/varnish/72df38fa8bfc0f5ca4a75d3e32657e8e590d85ab/http1-splitline
 * @description varnish-72df38fa8bfc0f5ca4a75d3e32657e8e590d85ab-bin/varnishd/http1/cache_http1_proto.c-http1_splitline CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vp_221, VariableAccess target_0) {
		target_0.getTarget()=vp_221
}

predicate func_2(Variable vp_221, ExprStmt target_6) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("char *")
		and target_2.getRValue().(VariableAccess).getTarget()=vp_221
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_2.getRValue().(VariableAccess).getLocation()))
}

predicate func_3(Variable vp_221, ExprStmt target_8, LogicalAndExpr target_9, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("char *")
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vp_221
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("char *")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_3)
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vp_221, PointerDereferenceExpr target_10, PostfixIncrExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vp_221
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_10.getOperand().(VariableAccess).getLocation())
}

predicate func_6(Variable vp_221, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="e"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_221
}

predicate func_8(Variable vp_221, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="b"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_221
}

predicate func_9(Variable vp_221, LogicalAndExpr target_9) {
		target_9.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vp_221
		and target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_9.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("vct_iscrlf")
		and target_9.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_221
		and target_9.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
}

predicate func_10(Variable vp_221, PointerDereferenceExpr target_10) {
		target_10.getOperand().(VariableAccess).getTarget()=vp_221
}

from Function func, Variable vp_221, VariableAccess target_0, PostfixIncrExpr target_5, ExprStmt target_6, ExprStmt target_8, LogicalAndExpr target_9, PointerDereferenceExpr target_10
where
func_0(vp_221, target_0)
and not func_2(vp_221, target_6)
and not func_3(vp_221, target_8, target_9, func)
and func_5(vp_221, target_10, target_5)
and func_6(vp_221, target_6)
and func_8(vp_221, target_8)
and func_9(vp_221, target_9)
and func_10(vp_221, target_10)
and vp_221.getType().hasName("char *")
and vp_221.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
