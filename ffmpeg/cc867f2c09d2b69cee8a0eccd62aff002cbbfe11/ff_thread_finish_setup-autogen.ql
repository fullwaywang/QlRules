/**
 * @name ffmpeg-cc867f2c09d2b69cee8a0eccd62aff002cbbfe11-ff_thread_finish_setup
 * @id cpp/ffmpeg/cc867f2c09d2b69cee8a0eccd62aff002cbbfe11/ff-thread-finish-setup
 * @description ffmpeg-cc867f2c09d2b69cee8a0eccd62aff002cbbfe11-libavcodec/pthread_frame.c-ff_thread_finish_setup CVE-2022-48434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="stash_hwaccel"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vavctx_640, Variable vp_641, LogicalAndExpr target_4, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stash_hwaccel"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_641
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_640
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_1)
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vavctx_640, Variable vp_641, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stash_hwaccel_context"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_641
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel_context"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_640
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vavctx_640, Variable vp_641, ExprStmt target_5, AddressOfExpr target_6, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stash_hwaccel_priv"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="parent"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_641
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="hwaccel_priv_data"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="internal"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_640
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_3)
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vavctx_640, LogicalAndExpr target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_640
		and target_4.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="caps_internal"
		and target_4.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hwaccel"
		and target_4.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_640
		and target_4.getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="1"
}

predicate func_5(Parameter vavctx_640, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_640
		and target_5.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Multiple ff_thread_finish_setup() calls\n"
}

predicate func_6(Variable vp_641, AddressOfExpr target_6) {
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="progress_mutex"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_641
}

from Function func, Parameter vavctx_640, Variable vp_641, LogicalAndExpr target_4, ExprStmt target_5, AddressOfExpr target_6
where
not func_0(func)
and not func_1(vavctx_640, vp_641, target_4, func)
and not func_2(vavctx_640, vp_641, func)
and not func_3(vavctx_640, vp_641, target_5, target_6, func)
and func_4(vavctx_640, target_4)
and func_5(vavctx_640, target_5)
and func_6(vp_641, target_6)
and vavctx_640.getType().hasName("AVCodecContext *")
and vp_641.getType().hasName("PerThreadContext *")
and vavctx_640.getParentScope+() = func
and vp_641.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
