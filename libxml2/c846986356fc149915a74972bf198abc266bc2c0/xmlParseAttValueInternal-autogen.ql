/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseAttValueInternal
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseAttValueInternal
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseAttValueInternal CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="1000000000"
		and target_0.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="1000000000"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_1)
}

predicate func_8(Parameter vctxt_8950) {
	exists(BitwiseAndExpr target_8 |
		target_8.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_8.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_8950)
}

predicate func_9(Function func) {
	exists(Literal target_9 |
		target_9.getValue()="10000000"
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Parameter vctxt_8950, Variable vin_8954, Variable vstart_8954) {
	exists(LogicalAndExpr target_10 |
		target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vin_8954
		and target_10.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstart_8954
		and target_10.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_10.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsg")
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_8950
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="AttValue length too long\n"
		and target_10.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vctxt_8950, Variable vin_8954, Variable vstart_8954
where
func_0(func)
and not func_1(func)
and func_8(vctxt_8950)
and func_9(func)
and func_10(vctxt_8950, vin_8954, vstart_8954)
and vctxt_8950.getType().hasName("xmlParserCtxtPtr")
and vin_8954.getType().hasName("const xmlChar *")
and vstart_8954.getType().hasName("const xmlChar *")
and vctxt_8950.getParentScope+() = func
and vin_8954.getParentScope+() = func
and vstart_8954.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
