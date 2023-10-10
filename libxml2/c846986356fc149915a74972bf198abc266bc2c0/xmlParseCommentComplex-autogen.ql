/**
 * @name libxml2-c846986356fc149915a74972bf198abc266bc2c0-xmlParseCommentComplex
 * @id cpp/libxml2/c846986356fc149915a74972bf198abc266bc2c0/xmlParseCommentComplex
 * @description libxml2-c846986356fc149915a74972bf198abc266bc2c0-parser.c-xmlParseCommentComplex CVE-2022-40303
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

predicate func_2(Parameter vctxt_4739, BitwiseAndExpr target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_4739
}

predicate func_4(Parameter vlen_4740, BlockStmt target_5, LogicalAndExpr target_4) {
		target_4.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_4740
		and target_4.getAnOperand().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_4.getAnOperand().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_4.getAnOperand().(EqualityOperation).getAnOperand() instanceof Literal
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Parameter vctxt_4739, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlFatalErrMsgStr")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_4739
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Comment too big found"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getStmt(2).(ReturnStmt).toString() = "return ..."
}

from Function func, Parameter vlen_4740, Parameter vctxt_4739, Literal target_0, BitwiseAndExpr target_2, LogicalAndExpr target_4, BlockStmt target_5
where
func_0(func, target_0)
and func_2(vctxt_4739, target_2)
and func_4(vlen_4740, target_5, target_4)
and func_5(vctxt_4739, target_5)
and vlen_4740.getType().hasName("size_t")
and vctxt_4739.getType().hasName("xmlParserCtxtPtr")
and vlen_4740.getParentScope+() = func
and vctxt_4739.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
