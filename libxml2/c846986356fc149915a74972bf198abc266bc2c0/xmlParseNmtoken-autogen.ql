/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNmtoken
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseNmtoken
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNmtoken CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmax_3689) {
	exists(VariableAccess target_0 |
		target_0.getTarget()=vmax_3689)
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

predicate func_5(Parameter vctxt_3653) {
	exists(BitwiseAndExpr target_5 |
		target_5.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_5.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3653)
}

predicate func_7(Function func) {
	exists(Literal target_7 |
		target_7.getValue()="50000"
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Variable vbuffer_3688, Variable vmax_3689, Variable vxmlFree, Parameter vctxt_3653) {
	exists(LogicalAndExpr target_8 |
		target_8.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_3689
		and target_8.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_8.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_8.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3653
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="NmToken"
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getTarget()=vxmlFree
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vbuffer_3688
		and target_8.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_9(Variable vlen_3655, Parameter vctxt_3653) {
	exists(LogicalAndExpr target_9 |
		target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3655
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="50000"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3653
		and target_9.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3653
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="NmToken"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_11(Variable vlen_3655) {
	exists(EqualityOperation target_11 |
		target_11.getAnOperand().(VariableAccess).getTarget()=vlen_3655
		and target_11.getAnOperand().(Literal).getValue()="0"
		and target_11.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Variable vlen_3655, Variable vbuffer_3688, Variable vmax_3689, Variable vxmlFree, Parameter vctxt_3653
where
func_0(vmax_3689)
and func_1(func)
and not func_2(func)
and func_5(vctxt_3653)
and func_7(func)
and func_8(vbuffer_3688, vmax_3689, vxmlFree, vctxt_3653)
and func_9(vlen_3655, vctxt_3653)
and vlen_3655.getType().hasName("int")
and func_11(vlen_3655)
and vbuffer_3688.getType().hasName("xmlChar *")
and vmax_3689.getType().hasName("int")
and vxmlFree.getType().hasName("xmlFreeFunc")
and vctxt_3653.getType().hasName("xmlParserCtxtPtr")
and vlen_3655.getParentScope+() = func
and vbuffer_3688.getParentScope+() = func
and vmax_3689.getParentScope+() = func
and not vxmlFree.getParentScope+() = func
and vctxt_3653.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
