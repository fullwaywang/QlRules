/**
 * @name ffmpeg-cdd5df8189ff1537f7abe8defe971f80602cc2d2-filter_frame
 * @id cpp/ffmpeg/cdd5df8189ff1537f7abe8defe971f80602cc2d2/filter-frame
 * @description ffmpeg-cdd5df8189ff1537f7abe8defe971f80602cc2d2-libavfilter/vf_fps.c-filter_frame CVE-2013-7021
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_174, ExprStmt target_2, FunctionCall target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("av_fifo_size")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fifo"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_174
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_2.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbuf_171, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="pts"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_171
		and target_1.getAnOperand().(Literal).getValue()="9223372036854775808"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
}

predicate func_2(Variable vs_174, ExprStmt target_2) {
		target_2.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getTarget().getName()="drop"
		and target_2.getExpr().(PostfixIncrExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_174
}

predicate func_3(Parameter vbuf_171, Variable vs_174, FunctionCall target_3) {
		target_3.getTarget().hasName("write_to_fifo")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="fifo"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_174
		and target_3.getArgument(1).(VariableAccess).getTarget()=vbuf_171
}

from Function func, Parameter vbuf_171, Variable vs_174, EqualityOperation target_1, ExprStmt target_2, FunctionCall target_3
where
not func_0(vs_174, target_2, target_3)
and func_1(vbuf_171, target_1)
and func_2(vs_174, target_2)
and func_3(vbuf_171, vs_174, target_3)
and vbuf_171.getType().hasName("AVFrame *")
and vs_174.getType().hasName("FPSContext *")
and vbuf_171.getFunction() = func
and vs_174.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
