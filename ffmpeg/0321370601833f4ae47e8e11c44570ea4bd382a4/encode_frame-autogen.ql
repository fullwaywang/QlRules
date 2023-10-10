/**
 * @name ffmpeg-0321370601833f4ae47e8e11c44570ea4bd382a4-encode_frame
 * @id cpp/ffmpeg/0321370601833f4ae47e8e11c44570ea4bd382a4/encode-frame
 * @description ffmpeg-0321370601833f4ae47e8e11c44570ea4bd382a4-libavcodec/zmbvenc.c-encode_frame CVE-2019-13312
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(ArrayExpr).getParent().(AssignExpr).getRValue() instanceof ArrayExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vavctx_145, Variable vpalptr_151, ExprStmt target_37, RelationalOperation target_38) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pix_fmt"
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_1.getThen() instanceof ArrayExpr
		and target_1.getElse().(Literal).getValue()="0"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpalptr_151
		and target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_38.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vpalptr_151) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand() instanceof NotExpr
		and target_2.getAnOperand().(VariableAccess).getTarget()=vpalptr_151)
}

predicate func_5(Variable vc_148, Variable vpalptr_151, VariableAccess target_39, ExprStmt target_17, PointerArithmeticOperation target_40) {
	exists(IfStmt target_5 |
		target_5.getCondition().(VariableAccess).getTarget()=vpalptr_151
		and target_5.getThen().(BlockStmt).getStmt(0) instanceof ForStmt
		and target_5.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pal2"
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpalptr_151
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1024"
		and target_5.getThen().(BlockStmt).getStmt(3) instanceof ExprStmt
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
		and target_17.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_40.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vavctx_145, Variable vc_148, Variable vwork_size_154, RelationalOperation target_38, ExprStmt target_41, PointerArithmeticOperation target_40) {
	exists(MulExpr target_7 |
		target_7.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_7.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_7.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_7.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vwork_size_154
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_38.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_41.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_40.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Parameter vavctx_145, Variable vc_148, Variable vwork_size_154, ExprStmt target_42, ExprStmt target_43, ExprStmt target_44) {
	exists(MulExpr target_8 |
		target_8.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_8.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_8.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_8.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_8.getParent().(AssignAddExpr).getRValue() = target_8
		and target_8.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vwork_size_154
		and target_42.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_43.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_44.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(Variable vc_148, Variable vx_199, PointerArithmeticOperation target_45, ExprStmt target_46, ExprStmt target_47) {
	exists(MulExpr target_9 |
		target_9.getLeftOperand().(VariableAccess).getTarget()=vx_199
		and target_9.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_9.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_45.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_9.getLeftOperand().(VariableAccess).getLocation())
		and target_9.getLeftOperand().(VariableAccess).getLocation().isBefore(target_47.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_10(Variable vc_148, Variable vx_199, ExprStmt target_48, ExprStmt target_49) {
	exists(MulExpr target_10 |
		target_10.getLeftOperand().(VariableAccess).getTarget()=vx_199
		and target_10.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_10.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_10.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_48.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_49.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_11(Variable vc_148, Variable vmx_202, ExprStmt target_48, ExprStmt target_50, ExprStmt target_51) {
	exists(MulExpr target_11 |
		target_11.getLeftOperand().(VariableAccess).getTarget()=vmx_202
		and target_11.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_11.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_48.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_50.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_51.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getLocation().isBefore(target_11.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_12(Variable vc_148, Variable vi_156, Variable vbw2_199, ExprStmt target_52, ExprStmt target_50, ExprStmt target_46) {
	exists(MulExpr target_12 |
		target_12.getLeftOperand().(VariableAccess).getTarget()=vbw2_199
		and target_12.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_12.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_12.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_156
		and target_12.getParent().(LTExpr).getGreaterOperand().(VariableAccess).getTarget()=vbw2_199
		and target_12.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_52
		and target_50.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_46.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_13(Parameter vavctx_145, Variable vc_148, RelationalOperation target_53, ExprStmt target_54, ExprStmt target_55, ExprStmt target_56) {
	exists(MulExpr target_13 |
		target_13.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_13.getRightOperand().(PointerFieldAccess).getTarget().getName()="bypp"
		and target_13.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_53.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_54.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_55.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_56.getExpr().(AssignPointerAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_14(Variable vc_148, ExprStmt target_57, ExprStmt target_58) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="fmt"
		and target_14.getQualifier().(VariableAccess).getTarget()=vc_148
		and target_57.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getQualifier().(VariableAccess).getLocation())
		and target_14.getQualifier().(VariableAccess).getLocation().isBefore(target_58.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_15(Variable vp_149, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="data"
		and target_15.getQualifier().(VariableAccess).getTarget()=vp_149
		and target_15.getParent().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_16(Variable vi_156, VariableAccess target_39, ForStmt target_16) {
		target_16.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_156
		and target_16.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_16.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_156
		and target_16.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="256"
		and target_16.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_156
		and target_16.getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
}

predicate func_17(Variable vc_148, VariableAccess target_39, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_17.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_17.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_17.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pal"
		and target_17.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_17.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="768"
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
}

predicate func_18(Variable vwork_size_154, VariableAccess target_39, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwork_size_154
		and target_18.getExpr().(AssignExpr).getRValue().(Literal).getValue()="768"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_39
}

predicate func_19(Variable vbuf_150, VariableAccess target_59, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbuf_150
		and target_19.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

predicate func_20(Variable vbuf_150, VariableAccess target_59, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbuf_150
		and target_20.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_20.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

predicate func_21(Variable vbuf_150, VariableAccess target_59, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbuf_150
		and target_21.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_21.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

predicate func_22(Variable vbuf_150, VariableAccess target_59, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbuf_150
		and target_22.getExpr().(AssignExpr).getRValue().(Literal).getValue()="16"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

predicate func_23(Variable vbuf_150, VariableAccess target_59, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vbuf_150
		and target_23.getExpr().(AssignExpr).getRValue().(Literal).getValue()="16"
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_59
}

predicate func_24(Variable vkeyframe_152, NotExpr target_24) {
		target_24.getOperand().(VariableAccess).getTarget()=vkeyframe_152
}

predicate func_25(Variable vc_148, Variable vp_149, ArrayExpr target_25) {
		target_25.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_25.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_149
		and target_25.getArrayOffset().(Literal).getValue()="1"
		and target_25.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("memcmp")
		and target_25.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pal2"
		and target_25.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_25.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1024"
}

predicate func_26(Parameter vavctx_145, Variable vc_148, Variable vwork_size_154, PointerFieldAccess target_26) {
		target_26.getTarget().getName()="width"
		and target_26.getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_26.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vwork_size_154
}

predicate func_27(Parameter vavctx_145, Variable vwork_size_154, PointerFieldAccess target_27) {
		target_27.getTarget().getName()="width"
		and target_27.getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_27.getParent().(AssignAddExpr).getRValue() = target_27
		and target_27.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vwork_size_154
}

predicate func_28(Parameter vavctx_145, PointerFieldAccess target_28) {
		target_28.getTarget().getName()="width"
		and target_28.getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_28.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
}

predicate func_29(Variable vmx_202, VariableAccess target_29) {
		target_29.getTarget()=vmx_202
}

predicate func_30(Variable vx_199, VariableAccess target_30) {
		target_30.getTarget()=vx_199
}

predicate func_31(Variable vx_199, VariableAccess target_31) {
		target_31.getTarget()=vx_199
}

predicate func_32(Variable vi_156, Variable vbw2_199, ExprStmt target_52, VariableAccess target_32) {
		target_32.getTarget()=vbw2_199
		and target_32.getParent().(LTExpr).getLesserOperand().(VariableAccess).getTarget()=vi_156
		and target_32.getParent().(LTExpr).getParent().(ForStmt).getStmt()=target_52
}

predicate func_33(Variable vp_149, Variable vpalptr_151, ArrayExpr target_25, ExprStmt target_60, ExprStmt target_61, ArrayExpr target_33) {
		target_33.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_33.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_149
		and target_33.getArrayOffset() instanceof Literal
		and target_33.getParent().(AssignExpr).getRValue() = target_33
		and target_33.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpalptr_151
		and target_25.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_33.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_33.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_60.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_33.getParent().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_61.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
}

predicate func_34(Variable vc_148, Variable vp_149, ExprStmt target_62, ExprStmt target_63, ExprStmt target_60, ArrayExpr target_35, ArrayExpr target_34) {
		target_34.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_34.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_149
		and target_34.getArrayOffset().(Literal).getValue()="1"
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pal2"
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1024"
		and target_62.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_34.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_63.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_60.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_34.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_34.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_35.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_35(Variable vc_148, Variable vp_149, ExprStmt target_17, PointerArithmeticOperation target_40, ArrayExpr target_34, ExprStmt target_64, ArrayExpr target_35) {
		target_35.getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_35.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_149
		and target_35.getArrayOffset().(Literal).getValue()="1"
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="pal2"
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1024"
		and target_17.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_35.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_40.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_34.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_35.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_35.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_64.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_37(Parameter vavctx_145, Variable vkeyframe_152, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="key_frame"
		and target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="coded_frame"
		and target_37.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_37.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vkeyframe_152
}

predicate func_38(Parameter vavctx_145, Variable vi_156, RelationalOperation target_38) {
		 (target_38 instanceof GTExpr or target_38 instanceof LTExpr)
		and target_38.getLesserOperand().(VariableAccess).getTarget()=vi_156
		and target_38.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_38.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
}

predicate func_39(Variable vkeyframe_152, VariableAccess target_39) {
		target_39.getTarget()=vkeyframe_152
}

predicate func_40(Variable vc_148, Variable vwork_size_154, PointerArithmeticOperation target_40) {
		target_40.getAnOperand().(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_40.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_40.getAnOperand().(VariableAccess).getTarget()=vwork_size_154
}

predicate func_41(Parameter vavctx_145, Variable vwork_size_154, ExprStmt target_41) {
		target_41.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vwork_size_154
		and target_41.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_41.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
}

predicate func_42(Parameter vavctx_145, Variable vc_148, Variable vwork_size_154, ExprStmt target_42) {
		target_42.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_42.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_42.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_42.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vwork_size_154
		and target_42.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_42.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
}

predicate func_43(Parameter vavctx_145, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_43.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_43.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(SubExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="16"
		and target_43.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_43.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="16"
}

predicate func_44(Variable vc_148, Variable vwork_size_154, ExprStmt target_44) {
		target_44.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_44.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_44.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vwork_size_154
}

predicate func_45(Variable vc_148, Variable vwork_size_154, PointerArithmeticOperation target_45) {
		target_45.getAnOperand().(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_45.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_45.getAnOperand().(VariableAccess).getTarget()=vwork_size_154
}

predicate func_46(Parameter vavctx_145, Variable vx_199, Variable vbw2_199, ExprStmt target_46) {
		target_46.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbw2_199
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vx_199
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="16"
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="16"
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
		and target_46.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vx_199
}

predicate func_47(Variable vx_199, ExprStmt target_47) {
		target_47.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vx_199
}

predicate func_48(Variable vc_148, Variable vp_149, Variable vx_199, Variable vmx_202, ExprStmt target_48) {
		target_48.getExpr().(FunctionCall).getTarget().hasName("zmbv_me")
		and target_48.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_148
		and target_48.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_48.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_149
		and target_48.getExpr().(FunctionCall).getArgument(2).(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_48.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="pstride"
		and target_48.getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_48.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vx_199
		and target_48.getExpr().(FunctionCall).getArgument(7).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmx_202
}

predicate func_49(Variable vx_199, ExprStmt target_49) {
		target_49.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vx_199
}

predicate func_50(Variable vc_148, Variable vmx_202, ExprStmt target_50) {
		target_50.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vmx_202
		and target_50.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="pstride"
		and target_50.getExpr().(AssignPointerAddExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
}

predicate func_51(Variable vmx_202, ExprStmt target_51) {
		target_51.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_51.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vmx_202
		and target_51.getExpr().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
}

predicate func_52(Variable vc_148, Variable vwork_size_154, Variable vi_156, ExprStmt target_52) {
		target_52.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="work_buf"
		and target_52.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_52.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vwork_size_154
		and target_52.getExpr().(AssignExpr).getRValue().(BitwiseXorExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_156
		and target_52.getExpr().(AssignExpr).getRValue().(BitwiseXorExpr).getRightOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_156
}

predicate func_53(Parameter vavctx_145, Variable vi_156, RelationalOperation target_53) {
		 (target_53 instanceof GTExpr or target_53 instanceof LTExpr)
		and target_53.getLesserOperand().(VariableAccess).getTarget()=vi_156
		and target_53.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_53.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_145
}

predicate func_54(Parameter vavctx_145, ExprStmt target_54) {
		target_54.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_54.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_145
		and target_54.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_54.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Error compressing data\n"
}

predicate func_55(Variable vc_148, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="prev"
		and target_55.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
}

predicate func_56(Variable vc_148, ExprStmt target_56) {
		target_56.getExpr().(AssignPointerAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="pstride"
		and target_56.getExpr().(AssignPointerAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
}

predicate func_57(Variable vc_148, Variable vkeyframe_152, ExprStmt target_57) {
		target_57.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="total_out"
		and target_57.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="zstream"
		and target_57.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_57.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_57.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(Literal).getValue()="6"
		and target_57.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vkeyframe_152
}

predicate func_58(Variable vc_148, Variable vbuf_150, ExprStmt target_58) {
		target_58.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_58.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_150
		and target_58.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="comp_buf"
		and target_58.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_58.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="total_out"
		and target_58.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="zstream"
		and target_58.getExpr().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
}

predicate func_59(Variable vkeyframe_152, VariableAccess target_59) {
		target_59.getTarget()=vkeyframe_152
}

predicate func_60(Variable vp_149, ExprStmt target_60) {
		target_60.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="data"
		and target_60.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_149
		and target_60.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

predicate func_61(Variable vpalptr_151, Variable vi_156, ExprStmt target_61) {
		target_61.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_61.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpalptr_151
		and target_61.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_156
}

predicate func_62(Variable vc_148, Variable vi_156, ExprStmt target_62) {
		target_62.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="pal"
		and target_62.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_62.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi_156
		and target_62.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_62.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_62.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
}

predicate func_63(Variable vc_148, Variable vpalptr_151, Variable vi_156, ExprStmt target_63) {
		target_63.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pal"
		and target_63.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_148
		and target_63.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerArithmeticOperation).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vi_156
		and target_63.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerArithmeticOperation).getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_63.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_63.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpalptr_151
		and target_63.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_156
}

predicate func_64(Variable vp_149, ExprStmt target_64) {
		target_64.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="linesize"
		and target_64.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vp_149
		and target_64.getExpr().(AssignPointerAddExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
}

from Function func, Parameter vavctx_145, Variable vc_148, Variable vp_149, Variable vbuf_150, Variable vpalptr_151, Variable vkeyframe_152, Variable vwork_size_154, Variable vi_156, Variable vx_199, Variable vbw2_199, Variable vmx_202, Literal target_0, PointerFieldAccess target_15, ForStmt target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, NotExpr target_24, ArrayExpr target_25, PointerFieldAccess target_26, PointerFieldAccess target_27, PointerFieldAccess target_28, VariableAccess target_29, VariableAccess target_30, VariableAccess target_31, VariableAccess target_32, ArrayExpr target_33, ArrayExpr target_34, ArrayExpr target_35, ExprStmt target_37, RelationalOperation target_38, VariableAccess target_39, PointerArithmeticOperation target_40, ExprStmt target_41, ExprStmt target_42, ExprStmt target_43, ExprStmt target_44, PointerArithmeticOperation target_45, ExprStmt target_46, ExprStmt target_47, ExprStmt target_48, ExprStmt target_49, ExprStmt target_50, ExprStmt target_51, ExprStmt target_52, RelationalOperation target_53, ExprStmt target_54, ExprStmt target_55, ExprStmt target_56, ExprStmt target_57, ExprStmt target_58, VariableAccess target_59, ExprStmt target_60, ExprStmt target_61, ExprStmt target_62, ExprStmt target_63, ExprStmt target_64
where
func_0(func, target_0)
and not func_1(vavctx_145, vpalptr_151, target_37, target_38)
and not func_2(vpalptr_151)
and not func_5(vc_148, vpalptr_151, target_39, target_17, target_40)
and not func_7(vavctx_145, vc_148, vwork_size_154, target_38, target_41, target_40)
and not func_8(vavctx_145, vc_148, vwork_size_154, target_42, target_43, target_44)
and not func_9(vc_148, vx_199, target_45, target_46, target_47)
and not func_10(vc_148, vx_199, target_48, target_49)
and not func_11(vc_148, vmx_202, target_48, target_50, target_51)
and not func_12(vc_148, vi_156, vbw2_199, target_52, target_50, target_46)
and not func_13(vavctx_145, vc_148, target_53, target_54, target_55, target_56)
and not func_14(vc_148, target_57, target_58)
and func_15(vp_149, target_15)
and func_16(vi_156, target_39, target_16)
and func_17(vc_148, target_39, target_17)
and func_18(vwork_size_154, target_39, target_18)
and func_19(vbuf_150, target_59, target_19)
and func_20(vbuf_150, target_59, target_20)
and func_21(vbuf_150, target_59, target_21)
and func_22(vbuf_150, target_59, target_22)
and func_23(vbuf_150, target_59, target_23)
and func_24(vkeyframe_152, target_24)
and func_25(vc_148, vp_149, target_25)
and func_26(vavctx_145, vc_148, vwork_size_154, target_26)
and func_27(vavctx_145, vwork_size_154, target_27)
and func_28(vavctx_145, target_28)
and func_29(vmx_202, target_29)
and func_30(vx_199, target_30)
and func_31(vx_199, target_31)
and func_32(vi_156, vbw2_199, target_52, target_32)
and func_33(vp_149, vpalptr_151, target_25, target_60, target_61, target_33)
and func_34(vc_148, vp_149, target_62, target_63, target_60, target_35, target_34)
and func_35(vc_148, vp_149, target_17, target_40, target_34, target_64, target_35)
and func_37(vavctx_145, vkeyframe_152, target_37)
and func_38(vavctx_145, vi_156, target_38)
and func_39(vkeyframe_152, target_39)
and func_40(vc_148, vwork_size_154, target_40)
and func_41(vavctx_145, vwork_size_154, target_41)
and func_42(vavctx_145, vc_148, vwork_size_154, target_42)
and func_43(vavctx_145, target_43)
and func_44(vc_148, vwork_size_154, target_44)
and func_45(vc_148, vwork_size_154, target_45)
and func_46(vavctx_145, vx_199, vbw2_199, target_46)
and func_47(vx_199, target_47)
and func_48(vc_148, vp_149, vx_199, vmx_202, target_48)
and func_49(vx_199, target_49)
and func_50(vc_148, vmx_202, target_50)
and func_51(vmx_202, target_51)
and func_52(vc_148, vwork_size_154, vi_156, target_52)
and func_53(vavctx_145, vi_156, target_53)
and func_54(vavctx_145, target_54)
and func_55(vc_148, target_55)
and func_56(vc_148, target_56)
and func_57(vc_148, vkeyframe_152, target_57)
and func_58(vc_148, vbuf_150, target_58)
and func_59(vkeyframe_152, target_59)
and func_60(vp_149, target_60)
and func_61(vpalptr_151, vi_156, target_61)
and func_62(vc_148, vi_156, target_62)
and func_63(vc_148, vpalptr_151, vi_156, target_63)
and func_64(vp_149, target_64)
and vavctx_145.getType().hasName("AVCodecContext *")
and vc_148.getType().hasName("ZmbvEncContext *const")
and vp_149.getType().hasName("const AVFrame *const")
and vbuf_150.getType().hasName("uint8_t *")
and vpalptr_151.getType().hasName("uint32_t *")
and vkeyframe_152.getType().hasName("int")
and vwork_size_154.getType().hasName("int")
and vi_156.getType().hasName("int")
and vx_199.getType().hasName("int")
and vbw2_199.getType().hasName("int")
and vmx_202.getType().hasName("int")
and vavctx_145.getParentScope+() = func
and vc_148.getParentScope+() = func
and vp_149.getParentScope+() = func
and vbuf_150.getParentScope+() = func
and vpalptr_151.getParentScope+() = func
and vkeyframe_152.getParentScope+() = func
and vwork_size_154.getParentScope+() = func
and vi_156.getParentScope+() = func
and vx_199.getParentScope+() = func
and vbw2_199.getParentScope+() = func
and vmx_202.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
