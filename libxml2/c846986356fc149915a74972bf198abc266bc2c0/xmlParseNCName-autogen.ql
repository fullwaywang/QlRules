/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNCName
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseNCName
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-parser.c-xmlParseNCName CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="0"
		and not target_1.getValue()="10000000"
		and target_1.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getEnclosingFunction() = func
}

predicate func_4(Parameter vctxt_3459, BitwiseAndExpr target_4) {
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3459
}

predicate func_6(Variable vcount_3462, BlockStmt target_8, LogicalAndExpr target_6) {
		target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_3462
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen()=target_8
}

/*predicate func_7(Variable vcount_3462, ExprStmt target_9, VariableAccess target_7) {
		target_7.getTarget()=vcount_3462
		and target_7.getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
}

*/
predicate func_8(Parameter vctxt_3459, BlockStmt target_8) {
		target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3459
		and target_8.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="NCName"
		and target_8.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_9(Parameter vctxt_3459, Variable vcount_3462, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlDictLookup")
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="dict"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3459
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="cur"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="input"
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3459
		and target_9.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcount_3462
}

from Function func, Parameter vctxt_3459, Variable vcount_3462, Literal target_1, BitwiseAndExpr target_4, LogicalAndExpr target_6, BlockStmt target_8, ExprStmt target_9
where
func_1(func, target_1)
and func_4(vctxt_3459, target_4)
and func_6(vcount_3462, target_8, target_6)
and func_8(vctxt_3459, target_8)
and func_9(vctxt_3459, vcount_3462, target_9)
and vctxt_3459.getType().hasName("xmlParserCtxtPtr")
and vcount_3462.getType().hasName("int")
and vctxt_3459.getParentScope+() = func
and vcount_3462.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
