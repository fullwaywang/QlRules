/**
 * @name libarchive-f0b1dbbc325a2d922015eee402b72edd422cb9ea-compress_bidder_bid
 * @id cpp/libarchive/f0b1dbbc325a2d922015eee402b72edd422cb9ea/compress-bidder-bid
 * @description libarchive-f0b1dbbc325a2d922015eee402b72edd422cb9ea-libarchive/archive_read_support_filter_compress.c-compress_bidder_bid CVE-2015-8932
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="2"
		and not target_0.getValue()="3"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("__archive_read_filter_ahead")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="16"
		and not target_1.getValue()="18"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Variable vbuffer_182, LogicalOrExpr target_4, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_182
		and target_2.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_2.getCondition().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="32"
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_2)
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_3(Variable vbuffer_182, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_182
		and target_3.getCondition().(BitwiseAndExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_3.getCondition().(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="64"
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_3))
}

predicate func_4(Variable vbuffer_182, LogicalOrExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_182
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="31"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbuffer_182
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="157"
}

from Function func, Variable vbuffer_182, Literal target_0, Literal target_1, LogicalOrExpr target_4
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(vbuffer_182, target_4, func)
and not func_3(vbuffer_182, func)
and func_4(vbuffer_182, target_4)
and vbuffer_182.getType().hasName("const unsigned char *")
and vbuffer_182.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
