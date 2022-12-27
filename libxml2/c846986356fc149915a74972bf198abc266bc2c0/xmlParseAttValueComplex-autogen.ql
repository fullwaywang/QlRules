/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseAttValueComplex
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseAttValueComplex
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseAttValueComplex CVE-2022-40303
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

predicate func_1(Variable vlen_3906) {
	exists(VariableAccess target_1 |
		target_1.getTarget()=vlen_3906
		and target_1.getParent().(GEExpr).getLesserOperand() instanceof Literal
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen() instanceof BlockStmt)
}

predicate func_2(Function func) {
	exists(DeclStmt target_2 |
		target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition() instanceof BitwiseAndExpr
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(Literal).getValue()="1000000000"
		and target_2.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getStmt(5)=target_2)
}

predicate func_3(Parameter vctxt_3902) {
	exists(BitwiseAndExpr target_3 |
		target_3.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_3.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3902)
}

predicate func_4(Function func) {
	exists(Literal target_4 |
		target_4.getValue()="10000000"
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vctxt_3902, Variable vlen_3906) {
	exists(LogicalAndExpr target_5 |
		target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3906
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_5.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_5.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsg")
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3902
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="AttValue length too long\n"
		and target_5.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ...")
}

predicate func_6(Parameter vctxt_3902, Variable vlen_3906, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3906
		and target_6.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsg")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3902
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="AttValue length too long\n"
		and target_6.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

from Function func, Parameter vctxt_3902, Variable vlen_3906
where
func_0(func)
and func_1(vlen_3906)
and not func_2(func)
and func_3(vctxt_3902)
and func_4(func)
and func_5(vctxt_3902, vlen_3906)
and func_6(vctxt_3902, vlen_3906, func)
and vctxt_3902.getType().hasName("xmlParserCtxtPtr")
and vlen_3906.getType().hasName("size_t")
and vctxt_3902.getParentScope+() = func
and vlen_3906.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
