/**
 * @name ffmpeg-e371f031b942d73e02c090170975561fabd5c264-decode_zbuf
 * @id cpp/ffmpeg/e371f031b942d73e02c090170975561fabd5c264/decode-zbuf
 * @description ffmpeg-e371f031b942d73e02c090170975561fabd5c264-libavcodec/pngdec.c-decode_zbuf CVE-2017-7866
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbuf_size_427, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_bprint_get_buffer")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_size_427
}

predicate func_1(Variable vbuf_size_427, BlockStmt target_6, AddressOfExpr target_7, ExprStmt target_8) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getLesserOperand().(VariableAccess).getTarget()=vbuf_size_427
		and target_1.getGreaterOperand().(Literal).getValue()="2"
		and target_1.getParent().(IfStmt).getThen()=target_6
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbuf_size_427, NotExpr target_5) {
	exists(SubExpr target_2 |
		target_2.getLeftOperand().(VariableAccess).getTarget()=vbuf_size_427
		and target_2.getRightOperand().(Literal).getValue()="1"
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="avail_out"
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vbuf_size_427, BlockStmt target_6, VariableAccess target_3) {
		target_3.getTarget()=vbuf_size_427
		and target_3.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_4(Variable vbuf_size_427, VariableAccess target_4) {
		target_4.getTarget()=vbuf_size_427
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="avail_out"
}

predicate func_5(Variable vbuf_size_427, BlockStmt target_6, NotExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vbuf_size_427
		and target_5.getParent().(IfStmt).getThen()=target_6
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-12"
		and target_6.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_6.getStmt(1).(GotoStmt).getName() ="fail"
}

predicate func_7(Variable vbuf_size_427, AddressOfExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vbuf_size_427
}

predicate func_8(Variable vbuf_size_427, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="avail_out"
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuf_size_427
}

from Function func, Variable vbuf_size_427, Literal target_0, VariableAccess target_3, VariableAccess target_4, NotExpr target_5, BlockStmt target_6, AddressOfExpr target_7, ExprStmt target_8
where
func_0(vbuf_size_427, target_0)
and not func_1(vbuf_size_427, target_6, target_7, target_8)
and not func_2(vbuf_size_427, target_5)
and func_3(vbuf_size_427, target_6, target_3)
and func_4(vbuf_size_427, target_4)
and func_5(vbuf_size_427, target_6, target_5)
and func_6(target_6)
and func_7(vbuf_size_427, target_7)
and func_8(vbuf_size_427, target_8)
and vbuf_size_427.getType().hasName("unsigned int")
and vbuf_size_427.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
