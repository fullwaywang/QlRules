/**
 * @name ffmpeg-cc867f2c09d2b69cee8a0eccd62aff002cbbfe11-ff_frame_thread_free
 * @id cpp/ffmpeg/cc867f2c09d2b69cee8a0eccd62aff002cbbfe11/ff-frame-thread-free
 * @description ffmpeg-cc867f2c09d2b69cee8a0eccd62aff002cbbfe11-libavcodec/pthread_frame.c-ff_frame_thread_free CVE-2022-48434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vfctx_705, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="hwaccel_priv_data"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_thread"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vavctx_703, RelationalOperation target_20, Literal target_2) {
		target_2.getValue()="16"
		and not target_2.getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_703
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed to update user thread.\n"
		and target_20.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

/*predicate func_3(Function func, StringLiteral target_3) {
		target_3.getValue()="Failed to update user thread.\n"
		and not target_3.getValue()="Assertion %s failed at %s:%d\n"
		and target_3.getEnclosingFunction() = func
}

*/
predicate func_4(Parameter vavctx_703, ExprStmt target_21, Function func) {
	exists(DoStmt target_4 |
		target_4.getCondition() instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_4)
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_5(Parameter vavctx_703, BlockStmt target_22, ExprStmt target_21) {
	exists(NotExpr target_5 |
		target_5.getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_5.getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_5.getParent().(IfStmt).getThen()=target_22
		and target_5.getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_6(LogicalAndExpr target_23, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
		and target_6.getEnclosingFunction() = func)
}

*/
predicate func_7(Parameter vavctx_703, Variable vfctx_705, RelationalOperation target_20, LogicalAndExpr target_23, PointerFieldAccess target_24, Function func) {
	exists(DoStmt target_7 |
		target_7.getCondition().(Literal).getValue()="0"
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stash_hwaccel"
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_7.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_7.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_7.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("const AVHWAccel *")
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_7)
		and target_20.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_23.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vavctx_703, Variable vfctx_705, AddressOfExpr target_25, AddressOfExpr target_26, Function func) {
	exists(DoStmt target_8 |
		target_8.getCondition().(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stash_hwaccel_context"
		and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
		and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel_context"
		and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hwaccel_context"
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_8.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("void *")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_8)
		and target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_26.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(Parameter vavctx_703, Variable vfctx_705, FunctionCall target_27, RelationalOperation target_20, ExprStmt target_28, Function func) {
	exists(DoStmt target_9 |
		target_9.getCondition().(Literal).getValue()="0"
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stash_hwaccel_priv"
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel_priv_data"
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="hwaccel_priv_data"
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_9.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("void *")
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_9)
		and target_27.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_9.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_11(Parameter vavctx_703, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="hwaccel_priv_data"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
}

predicate func_12(Variable vfctx_705, VariableAccess target_12) {
		target_12.getTarget()=vfctx_705
}

predicate func_13(Variable vfctx_705, VariableAccess target_13) {
		target_13.getTarget()=vfctx_705
}

predicate func_14(Variable vfctx_705, VariableAccess target_14) {
		target_14.getTarget()=vfctx_705
}

predicate func_15(Parameter vavctx_703, VariableAccess target_15) {
		target_15.getTarget()=vavctx_703
		and target_15.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand() instanceof FunctionCall
}

predicate func_17(Parameter vavctx_703, VariableAccess target_17) {
		target_17.getTarget()=vavctx_703
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
}

predicate func_18(Parameter vavctx_703, Variable vfctx_705, Function func, IfStmt target_18) {
		target_18.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="prev_thread"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="hwaccel_priv_data"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="hwaccel_priv_data"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_18.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_thread"
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("update_context_from_thread")
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_703
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_thread"
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(2) instanceof Literal
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof Literal
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_703
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_18.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_18
}

/*predicate func_19(Variable vfctx_705, LogicalAndExpr target_23, PointerFieldAccess target_24, PointerFieldAccess target_19) {
		target_19.getTarget().getName()="avctx"
		and target_19.getQualifier().(PointerFieldAccess).getTarget().getName()="prev_thread"
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
		and target_23.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

*/
predicate func_20(Parameter vavctx_703, Variable vfctx_705, RelationalOperation target_20) {
		 (target_20 instanceof GTExpr or target_20 instanceof LTExpr)
		and target_20.getLesserOperand().(FunctionCall).getTarget().hasName("update_context_from_thread")
		and target_20.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_703
		and target_20.getLesserOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_20.getLesserOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="prev_thread"
		and target_20.getLesserOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
		and target_20.getLesserOperand().(FunctionCall).getArgument(2) instanceof Literal
		and target_20.getGreaterOperand() instanceof Literal
}

predicate func_21(Parameter vavctx_703, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_703
		and target_21.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_21.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
}

predicate func_22(Parameter vavctx_703, BlockStmt target_22) {
		target_22.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_22.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_703
		and target_22.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_22.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
}

predicate func_23(Variable vfctx_705, LogicalAndExpr target_23) {
		target_23.getAnOperand().(PointerFieldAccess).getTarget().getName()="prev_thread"
		and target_23.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
		and target_23.getAnOperand() instanceof EqualityOperation
}

predicate func_24(Variable vfctx_705, PointerFieldAccess target_24) {
		target_24.getTarget().getName()="avctx"
		and target_24.getQualifier().(PointerFieldAccess).getTarget().getName()="prev_thread"
		and target_24.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
}

predicate func_25(Parameter vavctx_703, AddressOfExpr target_25) {
		target_25.getOperand().(PointerFieldAccess).getTarget().getName()="thread_ctx"
		and target_25.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_25.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
}

predicate func_26(Variable vfctx_705, AddressOfExpr target_26) {
		target_26.getOperand().(PointerFieldAccess).getTarget().getName()="threads"
		and target_26.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfctx_705
}

predicate func_27(Parameter vavctx_703, FunctionCall target_27) {
		target_27.getTarget().hasName("ffcodec")
		and target_27.getArgument(0).(PointerFieldAccess).getTarget().getName()="codec"
		and target_27.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_703
}

predicate func_28(Variable vfctx_705, ExprStmt target_28) {
		target_28.getExpr().(FunctionCall).getTarget().hasName("ff_pthread_free")
		and target_28.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfctx_705
}

from Function func, Parameter vavctx_703, Variable vfctx_705, PointerFieldAccess target_0, Literal target_1, Literal target_2, PointerFieldAccess target_11, VariableAccess target_12, VariableAccess target_13, VariableAccess target_14, VariableAccess target_15, VariableAccess target_17, IfStmt target_18, RelationalOperation target_20, ExprStmt target_21, BlockStmt target_22, LogicalAndExpr target_23, PointerFieldAccess target_24, AddressOfExpr target_25, AddressOfExpr target_26, FunctionCall target_27, ExprStmt target_28
where
func_0(vfctx_705, target_0)
and func_1(func, target_1)
and func_2(vavctx_703, target_20, target_2)
and not func_4(vavctx_703, target_21, func)
and not func_7(vavctx_703, vfctx_705, target_20, target_23, target_24, func)
and not func_8(vavctx_703, vfctx_705, target_25, target_26, func)
and not func_9(vavctx_703, vfctx_705, target_27, target_20, target_28, func)
and func_11(vavctx_703, target_11)
and func_12(vfctx_705, target_12)
and func_13(vfctx_705, target_13)
and func_14(vfctx_705, target_14)
and func_15(vavctx_703, target_15)
and func_17(vavctx_703, target_17)
and func_18(vavctx_703, vfctx_705, func, target_18)
and func_20(vavctx_703, vfctx_705, target_20)
and func_21(vavctx_703, target_21)
and func_22(vavctx_703, target_22)
and func_23(vfctx_705, target_23)
and func_24(vfctx_705, target_24)
and func_25(vavctx_703, target_25)
and func_26(vfctx_705, target_26)
and func_27(vavctx_703, target_27)
and func_28(vfctx_705, target_28)
and vavctx_703.getType().hasName("AVCodecContext *")
and vfctx_705.getType().hasName("FrameThreadContext *")
and vavctx_703.getParentScope+() = func
and vfctx_705.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
