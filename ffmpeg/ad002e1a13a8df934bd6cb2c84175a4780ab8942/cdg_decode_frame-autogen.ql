/**
 * @name ffmpeg-ad002e1a13a8df934bd6cb2c84175a4780ab8942-cdg_decode_frame
 * @id cpp/ffmpeg/ad002e1a13a8df934bd6cb2c84175a4780ab8942/cdg-decode-frame
 * @description ffmpeg-ad002e1a13a8df934bd6cb2c84175a4780ab8942-libavcodec/cdgraphics.c-cdg_decode_frame CVE-2013-3674
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_size_265, RelationalOperation target_2, SubExpr target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vbuf_size_265
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_0)
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbuf_264, Variable vbuf_size_265, Variable vcdg_data_268, Function func, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("bytestream_get_buffer")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_264
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcdg_data_268
		and target_1.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbuf_size_265
		and target_1.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vbuf_size_265, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vbuf_size_265
		and target_2.getLesserOperand().(AddExpr).getValue()="24"
}

predicate func_3(Variable vbuf_size_265, SubExpr target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_265
		and target_3.getRightOperand().(Literal).getValue()="8"
}

from Function func, Variable vbuf_264, Variable vbuf_size_265, Variable vcdg_data_268, ExprStmt target_1, RelationalOperation target_2, SubExpr target_3
where
not func_0(vbuf_size_265, target_2, target_3, func)
and func_1(vbuf_264, vbuf_size_265, vcdg_data_268, func, target_1)
and func_2(vbuf_size_265, target_2)
and func_3(vbuf_size_265, target_3)
and vbuf_264.getType().hasName("const uint8_t *")
and vbuf_size_265.getType().hasName("int")
and vcdg_data_268.getType().hasName("uint8_t[16]")
and vbuf_264.(LocalVariable).getFunction() = func
and vbuf_size_265.(LocalVariable).getFunction() = func
and vcdg_data_268.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
