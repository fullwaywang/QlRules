/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParsePubidLiteral
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParsePubidLiteral
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParsePubidLiteral CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_4285) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vsize_4285)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="0"
		and not target_1.getValue()="10000000"
		and target_1.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="10000000"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_2)
}

predicate func_4(Parameter vctxt_4282) {
	exists(BitwiseAndExpr target_4 |
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4282)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="50000"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vsize_4285, Variable vxmlFree, Variable vbuf_4283, Parameter vctxt_4282) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_4285
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_4282
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Public ID"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_4283
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Variable vsize_4285, Variable vxmlFree, Variable vbuf_4283, Parameter vctxt_4282
where
func_0(vsize_4285)
and func_1(func)
and not func_2(func)
and func_4(vctxt_4282)
and func_5(func)
and func_6(vsize_4285, vxmlFree, vbuf_4283, vctxt_4282)
and vsize_4285.getType().hasName("int")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vbuf_4283.getType().hasName("xmlChar *")
and vctxt_4282.getType().hasName("xmlParserCtxtPtr")
and vsize_4285.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
and vbuf_4283.getParentScope+() = func
and vctxt_4282.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
