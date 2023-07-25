/**
 * @name ffmpeg-347cb14b7cba7560e53f4434b419b9d8800253e7-mov_read_keys
 * @id cpp/ffmpeg/347cb14b7cba7560e53f4434b419b9d8800253e7/mov-read-keys
 * @description ffmpeg-347cb14b7cba7560e53f4434b419b9d8800253e7-libavformat/mov.c-mov_read_keys CVE-2016-5199
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_2, Function func) {
	exists(SubExpr target_0 |
		target_0.getValue()="536870910"
		and target_0.getParent().(GTExpr).getLesserOperand() instanceof DivExpr
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(BlockStmt target_2, Function func, DivExpr target_1) {
		target_1.getValue()="536870911"
		and target_1.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_2
		and target_1.getEnclosingFunction() = func
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fc"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="The 'keys' atom with the invalid key count: %d\n"
		and target_2.getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
}

from Function func, DivExpr target_1, BlockStmt target_2
where
not func_0(target_2, func)
and func_1(target_2, func, target_1)
and func_2(target_2)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
