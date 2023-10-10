/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseAttValueComplex
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseAttValueComplex
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-parser.c-xmlParseAttValueComplex CVE-2022-40303
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="1000000000"
		and target_0.getParent().(EQExpr).getParent().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vlen_3906, BlockStmt target_8, VariableAccess target_1) {
		target_1.getTarget()=vlen_3906
		and target_1.getParent().(GEExpr).getLesserOperand() instanceof Literal
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_8
}

predicate func_2(Parameter vctxt_3902, BitwiseAndExpr target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_3902
}

predicate func_4(Variable vlen_3906, BlockStmt target_9, LogicalAndExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3906
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_4.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_4.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_4.getParent().(IfStmt).getThen()=target_9
}

predicate func_5(Parameter vctxt_3902, Variable vlen_3906, Function func, IfStmt target_5) {
		target_5.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_3906
		and target_5.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsg")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3902
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="AttValue length too long\n"
		and target_5.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_5.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="mem_error"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5
}

/*predicate func_6(Parameter vctxt_3902, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsg")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3902
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="AttValue length too long\n"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

*/
/*predicate func_7(RelationalOperation target_10, Function func, GotoStmt target_7) {
		target_7.toString() = "goto ..."
		and target_7.getName() ="mem_error"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_7.getEnclosingFunction() = func
}

*/
predicate func_8(BlockStmt target_8) {
		target_8.getStmt(0) instanceof ExprStmt
		and target_8.getStmt(1) instanceof GotoStmt
}

predicate func_9(Parameter vctxt_3902, BlockStmt target_9) {
		target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsg")
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3902
		and target_9.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="AttValue length too long\n"
		and target_9.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_9.getStmt(1).(GotoStmt).getName() ="mem_error"
}

predicate func_10(Variable vlen_3906, RelationalOperation target_10) {
		 (target_10 instanceof GEExpr or target_10 instanceof LEExpr)
		and target_10.getGreaterOperand().(VariableAccess).getTarget()=vlen_3906
		and target_10.getLesserOperand() instanceof Literal
}

predicate func_11(Parameter vctxt_3902, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("xmlNextChar")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3902
}

predicate func_12(Parameter vctxt_3902, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("xmlErrMemory")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_3902
		and target_12.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
}

from Function func, Parameter vctxt_3902, Variable vlen_3906, Literal target_0, VariableAccess target_1, BitwiseAndExpr target_2, LogicalAndExpr target_4, IfStmt target_5, BlockStmt target_8, BlockStmt target_9, RelationalOperation target_10, ExprStmt target_11, ExprStmt target_12
where
func_0(func, target_0)
and func_1(vlen_3906, target_8, target_1)
and func_2(vctxt_3902, target_2)
and func_4(vlen_3906, target_9, target_4)
and func_5(vctxt_3902, vlen_3906, func, target_5)
and func_8(target_8)
and func_9(vctxt_3902, target_9)
and func_10(vlen_3906, target_10)
and func_11(vctxt_3902, target_11)
and func_12(vctxt_3902, target_12)
and vctxt_3902.getType().hasName("xmlParserCtxtPtr")
and vlen_3906.getType().hasName("size_t")
and vctxt_3902.getParentScope+() = func
and vlen_3906.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
