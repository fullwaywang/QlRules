/**
 * @name jbig2dec-9d2c4f3bdb0bd003deae788e7187c0f86e624544-jbig2_sd_new
 * @id cpp/jbig2dec/9d2c4f3bdb0bd003deae788e7187c0f86e624544/jbig2-sd-new
 * @description jbig2dec-9d2c4f3bdb0bd003deae788e7187c0f86e624544-jbig2_symbol_dict.c-jbig2_sd_new CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, UnaryMinusExpr target_0) {
		target_0.getValue()="-1"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_0.getEnclosingFunction() = func
}

predicate func_1(RelationalOperation target_4, Function func, ReturnStmt target_1) {
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vctx_91, Parameter vn_symbols_91, Function func, IfStmt target_2) {
		target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vn_symbols_91
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_error")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_91
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof UnaryMinusExpr
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Negative number of symbols in symbol dict: %d"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vn_symbols_91
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

/*predicate func_3(Parameter vctx_91, Parameter vn_symbols_91, RelationalOperation target_4, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("jbig2_error")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctx_91
		and target_3.getExpr().(FunctionCall).getArgument(2) instanceof UnaryMinusExpr
		and target_3.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="Negative number of symbols in symbol dict: %d"
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vn_symbols_91
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

*/
predicate func_4(Parameter vn_symbols_91, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vn_symbols_91
		and target_4.getGreaterOperand() instanceof Literal
}

from Function func, Parameter vctx_91, Parameter vn_symbols_91, UnaryMinusExpr target_0, ReturnStmt target_1, IfStmt target_2, RelationalOperation target_4
where
func_0(func, target_0)
and func_1(target_4, func, target_1)
and func_2(vctx_91, vn_symbols_91, func, target_2)
and func_4(vn_symbols_91, target_4)
and vctx_91.getType().hasName("Jbig2Ctx *")
and vn_symbols_91.getType().hasName("uint32_t")
and vctx_91.getParentScope+() = func
and vn_symbols_91.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
