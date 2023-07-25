/**
 * @name varnish-1cb778f6f69737109e8c070a74b8e95b78f46d13-http1_splitline
 * @id cpp/varnish/1cb778f6f69737109e8c070a74b8e95b78f46d13/http1-splitline
 * @description varnish-1cb778f6f69737109e8c070a74b8e95b78f46d13-bin/varnishd/http1/cache_http1_proto.c-http1_splitline CVE-2019-15892
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="400"
		and target_0.getParent().(ArrayExpr).getParent().(EQExpr).getAnOperand() instanceof ArrayExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vp_221, Parameter vhtc_218, ExprStmt target_13) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vp_221
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_218
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_13.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vp_221, Parameter vhtc_218, FunctionCall target_15) {
	exists(NotExpr target_2 |
		target_2.getOperand().(FunctionCall).getTarget().hasName("vct_iscrlf")
		and target_2.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vp_221
		and target_2.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_2.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_218
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_2.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Variable vp_221, Parameter vhtc_218, ExprStmt target_17) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("vct_iscrlf")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vp_221
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="rxbuf_e"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_218
		and target_17.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vi_222, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vi_222
		and target_4.getThen().(ReturnStmt).getExpr().(Literal).getValue()="400"
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_4))
}

predicate func_6(Variable vp_221, VariableAccess target_6) {
		target_6.getTarget()=vp_221
		and target_6.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_7(Variable vp_221, VariableAccess target_7) {
		target_7.getTarget()=vp_221
		and target_7.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_8(Variable vp_221, VariableAccess target_8) {
		target_8.getTarget()=vp_221
		and target_8.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_9(Variable vp_221, LogicalOrExpr target_9) {
		target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_9.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
}

predicate func_10(Variable vp_221, Variable vi_222, ConditionalExpr target_10) {
		target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_10.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_10.getThen().(Literal).getValue()="2"
		and target_10.getElse().(Literal).getValue()="1"
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_222
}

/*predicate func_11(Variable vp_221, ExprStmt target_18, EqualityOperation target_11) {
		target_11.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_11.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_11.getAnOperand().(Literal).getValue()="13"
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_11.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="10"
		and target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_11.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

*/
/*predicate func_12(Variable vp_221, ExprStmt target_19, EqualityOperation target_12) {
		target_12.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_12.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_12.getAnOperand().(Literal).getValue()="10"
		and target_12.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_221
		and target_12.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_12.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="13"
		and target_12.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

*/
predicate func_13(Variable vp_221, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="b"
		and target_13.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_13.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_13.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_221
}

predicate func_15(Variable vp_221, Parameter vhtc_218, FunctionCall target_15) {
		target_15.getTarget().hasName("http1_dissect_hdrs")
		and target_15.getArgument(1).(VariableAccess).getTarget()=vp_221
		and target_15.getArgument(2).(VariableAccess).getTarget()=vhtc_218
}

predicate func_17(Variable vp_221, Parameter vhtc_218, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_221
		and target_17.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rxbuf_b"
		and target_17.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhtc_218
}

predicate func_18(Variable vp_221, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="e"
		and target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_18.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_18.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_221
}

predicate func_19(Variable vp_221, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vp_221
		and target_19.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

from Function func, Variable vp_221, Variable vi_222, Parameter vhtc_218, Literal target_0, VariableAccess target_6, VariableAccess target_7, VariableAccess target_8, LogicalOrExpr target_9, ConditionalExpr target_10, ExprStmt target_13, FunctionCall target_15, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19
where
func_0(func, target_0)
and not func_1(vp_221, vhtc_218, target_13)
and not func_2(vp_221, vhtc_218, target_15)
and not func_3(vp_221, vhtc_218, target_17)
and not func_4(vi_222, func)
and func_6(vp_221, target_6)
and func_7(vp_221, target_7)
and func_8(vp_221, target_8)
and func_9(vp_221, target_9)
and func_10(vp_221, vi_222, target_10)
and func_13(vp_221, target_13)
and func_15(vp_221, vhtc_218, target_15)
and func_17(vp_221, vhtc_218, target_17)
and func_18(vp_221, target_18)
and func_19(vp_221, target_19)
and vp_221.getType().hasName("char *")
and vi_222.getType().hasName("int")
and vhtc_218.getType().hasName("http_conn *")
and vp_221.getParentScope+() = func
and vi_222.getParentScope+() = func
and vhtc_218.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
