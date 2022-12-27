/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNCNameComplex
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseNCNameComplex
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseNCNameComplex CVE-2022-40303
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
	exists(Literal target_1 |
		target_1.getValue()="50000"
		and not target_1.getValue()="2147483647"
		and target_1.getParent().(GTExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="10000000"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_2)
}

predicate func_3(Variable vlen_3384, Variable vl_3384) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vlen_3384
		and target_3.getGreaterOperand().(SubExpr).getLeftOperand().(Literal).getValue()="2147483647"
		and target_3.getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vl_3384
		and target_3.getParent().(IfStmt).getThen() instanceof ExprStmt)
}

predicate func_5(Parameter vctxt_3383) {
	exists(BitwiseAndExpr target_5 |
		target_5.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_5.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3383)
}

predicate func_6(Variable vlen_3384, Variable vl_3384) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vlen_3384
		and target_6.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vl_3384)
}

predicate func_9(Parameter vctxt_3383, Variable vlen_3384) {
	exists(LogicalAndExpr target_9 |
		target_9.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3384
		and target_9.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_9.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_9.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErr")
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3383
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="NCName"
		and target_9.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_13(Parameter vctxt_3383, Variable vl_3384) {
	exists(AddressOfExpr target_13 |
		target_13.getOperand().(VariableAccess).getTarget()=vl_3384
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xmlCurrentChar")
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3383)
}

from Function func, Parameter vctxt_3383, Variable vlen_3384, Variable vl_3384
where
func_0(func)
and func_1(func)
and not func_2(func)
and not func_3(vlen_3384, vl_3384)
and func_5(vctxt_3383)
and func_6(vlen_3384, vl_3384)
and func_9(vctxt_3383, vlen_3384)
and vctxt_3383.getType().hasName("xmlParserCtxtPtr")
and vlen_3384.getType().hasName("int")
and vl_3384.getType().hasName("int")
and func_13(vctxt_3383, vl_3384)
and vctxt_3383.getParentScope+() = func
and vlen_3384.getParentScope+() = func
and vl_3384.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
