/**
 * @name ffmpeg-8c2ea3030af7b40a3c4275696fb5c76cdb80950a-decode_frame
 * @id cpp/ffmpeg/8c2ea3030af7b40a3c4275696fb5c76cdb80950a/decode-frame
 * @description ffmpeg-8c2ea3030af7b40a3c4275696fb5c76cdb80950a-libavcodec/pictordec.c-decode_frame CVE-2017-7862
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getEnclosingFunction() = func)
}

/*predicate func_1(Variable vs_104, Parameter vavctx_100, BlockStmt target_4, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_104
		and target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_100
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_104
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_1.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_100
		and target_1.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
}

*/
/*predicate func_2(Variable vs_104, Parameter vavctx_100, BlockStmt target_4, EqualityOperation target_2) {
		target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_104
		and target_2.getAnOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_2.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_100
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_104
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_100
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
}

*/
predicate func_3(BlockStmt target_4, Function func, LogicalAndExpr target_3) {
		target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getAnOperand() instanceof EqualityOperation
		and target_3.getParent().(IfStmt).getThen()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vs_104, Parameter vavctx_100, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ff_set_dimensions")
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_100
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="width"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_104
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_104
}

from Function func, Variable vs_104, Parameter vavctx_100, LogicalAndExpr target_3, BlockStmt target_4
where
not func_0(target_4, func)
and func_3(target_4, func, target_3)
and func_4(vs_104, vavctx_100, target_4)
and vs_104.getType().hasName("PicContext *")
and vavctx_100.getType().hasName("AVCodecContext *")
and vs_104.getParentScope+() = func
and vavctx_100.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
