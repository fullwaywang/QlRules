/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseStringName
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseStringName
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseStringName CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="10000000"
		and target_0.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="10000000"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_1)
}

predicate func_4(Parameter vctxt_3565) {
	exists(BitwiseAndExpr target_4 |
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3565)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="50000"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Variable vbuffer_3592, Variable vxmlFree, Variable vlen_3568, Parameter vctxt_3565) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3568
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3565
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="NCName"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_3592
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Variable vbuffer_3592, Variable vxmlFree, Variable vlen_3568, Parameter vctxt_3565
where
func_0(func)
and not func_1(func)
and func_4(vctxt_3565)
and func_5(func)
and func_6(vbuffer_3592, vxmlFree, vlen_3568, vctxt_3565)
and vbuffer_3592.getType().hasName("xmlChar *")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vlen_3568.getType().hasName("int")
and vctxt_3565.getType().hasName("xmlParserCtxtPtr")
and vbuffer_3592.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
and vlen_3568.getParentScope+() = func
and vctxt_3565.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
