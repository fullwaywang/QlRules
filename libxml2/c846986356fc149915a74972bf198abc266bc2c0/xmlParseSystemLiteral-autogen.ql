/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseSystemLiteral
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseSystemLiteral
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseSystemLiteral CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsize_4195) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vsize_4195)
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
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_2)
}

predicate func_4(Parameter vctxt_4192) {
	exists(BitwiseAndExpr target_4 |
		target_4.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_4.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4192)
}

predicate func_5(Function func) {
	exists(Literal target_5 |
		target_5.getValue()="50000"
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vctxt_4192, Variable vbuf_4193, Variable vsize_4195, Variable vstate_4198, Variable vxmlFree) {
	exists(LogicalAndExpr target_6 |
		target_6.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_4195
		and target_6.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_6.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_4192
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="SystemLiteral"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuf_4193
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="instate"
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4192
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstate_4198
		and target_6.getParent().(IfStmt).getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vctxt_4192, Variable vbuf_4193, Variable vsize_4195, Variable vstate_4198, Variable vxmlFree
where
func_0(vsize_4195)
and func_1(func)
and not func_2(func)
and func_4(vctxt_4192)
and func_5(func)
and func_6(vctxt_4192, vbuf_4193, vsize_4195, vstate_4198, vxmlFree)
and vctxt_4192.getType().hasName("xmlParserCtxtPtr")
and vbuf_4193.getType().hasName("xmlChar *")
and vsize_4195.getType().hasName("int")
and vstate_4198.getType().hasName("int")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vctxt_4192.getParentScope+() = func
and vbuf_4193.getParentScope+() = func
and vsize_4195.getParentScope+() = func
and vstate_4198.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
