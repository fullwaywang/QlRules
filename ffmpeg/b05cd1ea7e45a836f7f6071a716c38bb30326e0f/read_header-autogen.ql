/**
 * @name ffmpeg-b05cd1ea7e45a836f7f6071a716c38bb30326e0f-read_header
 * @id cpp/ffmpeg/b05cd1ea7e45a836f7f6071a716c38bb30326e0f/read-header
 * @description ffmpeg-b05cd1ea7e45a836f7f6071a716c38bb30326e0f-libavcodec/ffv1dec.c-read_header CVE-2013-7020
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Variable vstate_576, Variable vc_578, Parameter vf_574, ExprStmt target_15, RelationalOperation target_13, ExprStmt target_18) {
	exists(ConditionalExpr target_4 |
		target_4.getCondition() instanceof RelationalOperation
		and target_4.getThen().(FunctionCall).getTarget().hasName("get_symbol")
		and target_4.getThen().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_578
		and target_4.getThen().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstate_576
		and target_4.getThen().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getElse().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_4.getElse().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_4.getElse().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getThen().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_13.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getElse().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getElse().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vf_574, IfStmt target_14, LogicalOrExpr target_19) {
	exists(LogicalOrExpr target_5 |
		target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="colorspace"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_5.getAnOperand() instanceof EqualityOperation
		and target_14.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vf_574, RelationalOperation target_20, ExprStmt target_21, RelationalOperation target_13) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="colorspace"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(13)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vf_574, RelationalOperation target_20, IfStmt target_14) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(14)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Variable vstate_576, Variable vc_578, Parameter vf_574, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="colorspace"
		and target_8.getQualifier().(VariableAccess).getTarget()=vf_574
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_symbol")
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_578
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstate_576
		and target_8.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_9(Variable vstate_576, Variable vc_578, Parameter vf_574, PointerFieldAccess target_9) {
		target_9.getTarget().getName()="bits_per_raw_sample"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_9.getParent().(AssignExpr).getLValue() = target_9
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_symbol")
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_578
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstate_576
		and target_9.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

/*predicate func_10(Variable vstate_576, Variable vc_578, Parameter vf_574, FunctionCall target_10) {
		target_10.getTarget().hasName("get_symbol")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vc_578
		and target_10.getArgument(1).(VariableAccess).getTarget()=vstate_576
		and target_10.getArgument(2).(Literal).getValue()="0"
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_10.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_10.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
}

*/
predicate func_11(Parameter vf_574, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="plane_count"
		and target_11.getQualifier().(VariableAccess).getTarget()=vf_574
		and target_11.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof IfStmt
}

predicate func_12(Variable vchroma_planes_583, Parameter vf_574, EqualityOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vchroma_planes_583
		and target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="chroma_planes"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
}

predicate func_13(Parameter vf_574, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_13.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_13.getLesserOperand().(Literal).getValue()="0"
		and target_13.getParent().(IfStmt).getThen().(ExprStmt).getExpr() instanceof AssignExpr
}

predicate func_14(Variable vchroma_v_shift_583, Variable vtransparency_583, Parameter vf_574, RelationalOperation target_20, IfStmt target_14) {
		target_14.getCondition().(PointerFieldAccess).getTarget().getName()="plane_count"
		and target_14.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchroma_v_shift_583
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chroma_v_shift"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtransparency_583
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="transparency"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Invalid change of global parameters\n"
		and target_14.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
}

predicate func_15(Variable vstate_576, Variable vc_578, Parameter vf_574, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="colorspace"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_symbol")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_578
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstate_576
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_18(Parameter vf_574, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_18.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_19(Variable vchroma_v_shift_583, Variable vtransparency_583, Parameter vf_574, LogicalOrExpr target_19) {
		target_19.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_19.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_19.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chroma_h_shift"
		and target_19.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_19.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vchroma_v_shift_583
		and target_19.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="chroma_v_shift"
		and target_19.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtransparency_583
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="transparency"
		and target_19.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
}

predicate func_20(Parameter vf_574, RelationalOperation target_20) {
		 (target_20 instanceof GTExpr or target_20 instanceof LTExpr)
		and target_20.getLesserOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_20.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_20.getGreaterOperand().(Literal).getValue()="2"
}

predicate func_21(Variable vstate_576, Variable vc_578, Parameter vf_574, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="state_transition"
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vf_574
		and target_21.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_21.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("get_symbol")
		and target_21.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_578
		and target_21.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vstate_576
		and target_21.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_21.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="one_state"
		and target_21.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_578
		and target_21.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Variable vstate_576, Variable vc_578, Variable vchroma_planes_583, Variable vchroma_v_shift_583, Variable vtransparency_583, Parameter vf_574, PointerFieldAccess target_8, PointerFieldAccess target_9, PointerFieldAccess target_11, EqualityOperation target_12, RelationalOperation target_13, IfStmt target_14, ExprStmt target_15, ExprStmt target_18, LogicalOrExpr target_19, RelationalOperation target_20, ExprStmt target_21
where
not func_4(vstate_576, vc_578, vf_574, target_15, target_13, target_18)
and not func_5(vf_574, target_14, target_19)
and not func_6(vf_574, target_20, target_21, target_13)
and not func_7(vf_574, target_20, target_14)
and func_8(vstate_576, vc_578, vf_574, target_8)
and func_9(vstate_576, vc_578, vf_574, target_9)
and func_11(vf_574, target_11)
and func_12(vchroma_planes_583, vf_574, target_12)
and func_13(vf_574, target_13)
and func_14(vchroma_v_shift_583, vtransparency_583, vf_574, target_20, target_14)
and func_15(vstate_576, vc_578, vf_574, target_15)
and func_18(vf_574, target_18)
and func_19(vchroma_v_shift_583, vtransparency_583, vf_574, target_19)
and func_20(vf_574, target_20)
and func_21(vstate_576, vc_578, vf_574, target_21)
and vstate_576.getType().hasName("uint8_t[32]")
and vc_578.getType().hasName("RangeCoder *const")
and vchroma_planes_583.getType().hasName("int")
and vchroma_v_shift_583.getType().hasName("int")
and vtransparency_583.getType().hasName("int")
and vf_574.getType().hasName("FFV1Context *")
and vstate_576.(LocalVariable).getFunction() = func
and vc_578.(LocalVariable).getFunction() = func
and vchroma_planes_583.(LocalVariable).getFunction() = func
and vchroma_v_shift_583.(LocalVariable).getFunction() = func
and vtransparency_583.(LocalVariable).getFunction() = func
and vf_574.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
