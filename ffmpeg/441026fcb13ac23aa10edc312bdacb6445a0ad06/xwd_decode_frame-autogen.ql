/**
 * @name ffmpeg-441026fcb13ac23aa10edc312bdacb6445a0ad06-xwd_decode_frame
 * @id cpp/ffmpeg/441026fcb13ac23aa10edc312bdacb6445a0ad06/xwd-decode-frame
 * @description ffmpeg-441026fcb13ac23aa10edc312bdacb6445a0ad06-libavcodec/xwddec.c-xwd_decode_frame CVE-2017-9991
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbpp_38, BlockStmt target_4, LogicalAndExpr target_5) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbpp_38
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbpp_38, BlockStmt target_6, EqualityOperation target_7) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbpp_38
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_1.getAnOperand() instanceof EqualityOperation
		and target_1.getParent().(IfStmt).getThen()=target_6
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vpixdepth_39, BlockStmt target_4, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vpixdepth_39
		and target_2.getAnOperand().(Literal).getValue()="1"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vpixdepth_39, BlockStmt target_6, EqualityOperation target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vpixdepth_39
		and target_3.getAnOperand().(Literal).getValue()="8"
		and target_3.getParent().(IfStmt).getThen()=target_6
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pix_fmt"
}

predicate func_5(Variable vbpp_38, LogicalAndExpr target_5) {
		target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbpp_38
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbpp_38
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
}

predicate func_6(BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pix_fmt"
}

predicate func_7(Variable vbpp_38, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vbpp_38
		and target_7.getAnOperand().(Literal).getValue()="8"
}

from Function func, Variable vbpp_38, Variable vpixdepth_39, EqualityOperation target_2, EqualityOperation target_3, BlockStmt target_4, LogicalAndExpr target_5, BlockStmt target_6, EqualityOperation target_7
where
not func_0(vbpp_38, target_4, target_5)
and not func_1(vbpp_38, target_6, target_7)
and func_2(vpixdepth_39, target_4, target_2)
and func_3(vpixdepth_39, target_6, target_3)
and func_4(target_4)
and func_5(vbpp_38, target_5)
and func_6(target_6)
and func_7(vbpp_38, target_7)
and vbpp_38.getType().hasName("uint32_t")
and vpixdepth_39.getType().hasName("uint32_t")
and vbpp_38.getParentScope+() = func
and vpixdepth_39.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
