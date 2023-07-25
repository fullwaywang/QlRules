/**
 * @name libtiff-dd1bcc7abb26094e93636e85520f0d8f81ab0fab-computeInputPixelOffsets
 * @id cpp/libtiff/dd1bcc7abb26094e93636e85520f0d8f81ab0fab/computeInputPixelOffsets
 * @description libtiff-dd1bcc7abb26094e93636e85520f0d8f81ab0fab-tools/tiffcrop.c-computeInputPixelOffsets CVE-2022-2056
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_0.getArgument(0) instanceof MulExpr
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_1.getArgument(0) instanceof MulExpr
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_2.getArgument(0) instanceof MulExpr
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_3.getArgument(0) instanceof MulExpr
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Function func) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_4.getArgument(0) instanceof ValueFieldAccess
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_5.getArgument(0) instanceof ValueFieldAccess
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_6.getArgument(0) instanceof ValueFieldAccess
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Function func) {
	exists(FunctionCall target_7 |
		target_7.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_7.getArgument(0) instanceof ValueFieldAccess
		and target_7.getParent().(AssignExpr).getRValue() = target_7
		and target_7.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Function func) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_8.getArgument(0) instanceof ArrayExpr
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Function func) {
	exists(FunctionCall target_9 |
		target_9.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_9.getArgument(0) instanceof ArrayExpr
		and target_9.getParent().(AssignExpr).getRValue() = target_9
		and target_9.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Function func) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_10.getArgument(0) instanceof ArrayExpr
		and target_10.getParent().(AssignExpr).getRValue() = target_10
		and target_10.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_10.getEnclosingFunction() = func)
}

predicate func_11(Function func) {
	exists(FunctionCall target_11 |
		target_11.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_11.getArgument(0) instanceof ArrayExpr
		and target_11.getParent().(AssignExpr).getRValue() = target_11
		and target_11.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_11.getEnclosingFunction() = func)
}

predicate func_12(Function func) {
	exists(FunctionCall target_12 |
		target_12.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_12.getArgument(0) instanceof MulExpr
		and target_12.getParent().(AssignExpr).getRValue() = target_12
		and target_12.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(FunctionCall target_13 |
		target_13.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_13.getArgument(0) instanceof MulExpr
		and target_13.getParent().(AssignExpr).getRValue() = target_13
		and target_13.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Function func) {
	exists(FunctionCall target_14 |
		target_14.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_14.getArgument(0) instanceof MulExpr
		and target_14.getParent().(AssignExpr).getRValue() = target_14
		and target_14.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_14.getEnclosingFunction() = func)
}

predicate func_15(Function func) {
	exists(FunctionCall target_15 |
		target_15.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_15.getArgument(0) instanceof MulExpr
		and target_15.getParent().(AssignExpr).getRValue() = target_15
		and target_15.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_15.getEnclosingFunction() = func)
}

predicate func_16(Parameter vcrop_5214, BitwiseAndExpr target_40, BitwiseAndExpr target_41) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_16.getArgument(0).(PointerFieldAccess).getTarget().getName()="width"
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_16.getParent().(AssignExpr).getRValue() = target_16
		and target_16.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_40.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_41.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_17(Parameter vcrop_5214, BitwiseAndExpr target_41, BitwiseAndExpr target_42) {
	exists(FunctionCall target_17 |
		target_17.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_17.getArgument(0).(PointerFieldAccess).getTarget().getName()="length"
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_17.getParent().(AssignExpr).getRValue() = target_17
		and target_17.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_41.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_17.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_42.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_18(Function func) {
	exists(FunctionCall target_18 |
		target_18.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_18.getArgument(0) instanceof MulExpr
		and target_18.getParent().(AssignExpr).getRValue() = target_18
		and target_18.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_18.getEnclosingFunction() = func)
}

predicate func_19(Function func) {
	exists(FunctionCall target_19 |
		target_19.getTarget().hasName("_TIFFClampDoubleToUInt32")
		and target_19.getArgument(0) instanceof MulExpr
		and target_19.getParent().(AssignExpr).getRValue() = target_19
		and target_19.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
		and target_19.getEnclosingFunction() = func)
}

predicate func_20(Variable vi_5225, Variable vscale_5217, Variable vxres_5218, Parameter vcrop_5214, MulExpr target_20) {
		target_20.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="X1"
		and target_20.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_20.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_20.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5225
		and target_20.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_20.getRightOperand().(VariableAccess).getTarget()=vxres_5218
		and target_20.getParent().(AssignExpr).getRValue() = target_20
		and target_20.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_21(Variable vi_5225, Variable vscale_5217, Variable vxres_5218, Parameter vcrop_5214, MulExpr target_21) {
		target_21.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="X2"
		and target_21.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_21.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_21.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5225
		and target_21.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_21.getRightOperand().(VariableAccess).getTarget()=vxres_5218
		and target_21.getParent().(AssignExpr).getRValue() = target_21
		and target_21.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_22(Variable vi_5225, Variable vscale_5217, Variable vyres_5218, Parameter vcrop_5214, MulExpr target_22) {
		target_22.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="Y1"
		and target_22.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_22.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_22.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5225
		and target_22.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_22.getRightOperand().(VariableAccess).getTarget()=vyres_5218
		and target_22.getParent().(AssignExpr).getRValue() = target_22
		and target_22.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_23(Variable vi_5225, Variable vscale_5217, Variable vyres_5218, Parameter vcrop_5214, MulExpr target_23) {
		target_23.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="Y2"
		and target_23.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_23.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_23.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5225
		and target_23.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_23.getRightOperand().(VariableAccess).getTarget()=vyres_5218
		and target_23.getParent().(AssignExpr).getRValue() = target_23
		and target_23.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_24(Variable vi_5225, Parameter vcrop_5214, ValueFieldAccess target_24) {
		target_24.getTarget().getName()="X1"
		and target_24.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_24.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_24.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5225
}

predicate func_25(Variable vi_5225, Parameter vcrop_5214, ValueFieldAccess target_25) {
		target_25.getTarget().getName()="X2"
		and target_25.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_25.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_25.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5225
}

predicate func_26(Variable vi_5225, Parameter vcrop_5214, ValueFieldAccess target_26) {
		target_26.getTarget().getName()="Y1"
		and target_26.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_26.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_26.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5225
}

predicate func_27(Variable vi_5225, Parameter vcrop_5214, ValueFieldAccess target_27) {
		target_27.getTarget().getName()="Y2"
		and target_27.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="corners"
		and target_27.getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_27.getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5225
}

predicate func_28(Parameter vcrop_5214, ArrayExpr target_28) {
		target_28.getArrayBase().(PointerFieldAccess).getTarget().getName()="margins"
		and target_28.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_28.getArrayOffset().(Literal).getValue()="0"
		and target_28.getParent().(AssignExpr).getRValue() = target_28
		and target_28.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_29(Parameter vcrop_5214, ArrayExpr target_29) {
		target_29.getArrayBase().(PointerFieldAccess).getTarget().getName()="margins"
		and target_29.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_29.getArrayOffset().(Literal).getValue()="1"
		and target_29.getParent().(AssignExpr).getRValue() = target_29
		and target_29.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_30(Parameter vcrop_5214, ArrayExpr target_30) {
		target_30.getArrayBase().(PointerFieldAccess).getTarget().getName()="margins"
		and target_30.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_30.getArrayOffset().(Literal).getValue()="2"
		and target_30.getParent().(AssignExpr).getRValue() = target_30
		and target_30.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_31(Parameter vcrop_5214, ArrayExpr target_31) {
		target_31.getArrayBase().(PointerFieldAccess).getTarget().getName()="margins"
		and target_31.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_31.getArrayOffset().(Literal).getValue()="3"
		and target_31.getParent().(AssignExpr).getRValue() = target_31
		and target_31.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_32(Variable vscale_5217, Variable vyres_5218, Parameter vcrop_5214, MulExpr target_32) {
		target_32.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="margins"
		and target_32.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_32.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_32.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_32.getRightOperand().(VariableAccess).getTarget()=vyres_5218
		and target_32.getParent().(AssignExpr).getRValue() = target_32
		and target_32.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_33(Variable vscale_5217, Variable vxres_5218, Parameter vcrop_5214, MulExpr target_33) {
		target_33.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="margins"
		and target_33.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_33.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_33.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_33.getRightOperand().(VariableAccess).getTarget()=vxres_5218
		and target_33.getParent().(AssignExpr).getRValue() = target_33
		and target_33.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_34(Variable vscale_5217, Variable vyres_5218, Parameter vcrop_5214, MulExpr target_34) {
		target_34.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="margins"
		and target_34.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_34.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_34.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_34.getRightOperand().(VariableAccess).getTarget()=vyres_5218
		and target_34.getParent().(AssignExpr).getRValue() = target_34
		and target_34.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_35(Variable vscale_5217, Variable vxres_5218, Parameter vcrop_5214, MulExpr target_35) {
		target_35.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="margins"
		and target_35.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_35.getLeftOperand().(MulExpr).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_35.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_35.getRightOperand().(VariableAccess).getTarget()=vxres_5218
		and target_35.getParent().(AssignExpr).getRValue() = target_35
		and target_35.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_36(Parameter vcrop_5214, PointerFieldAccess target_36) {
		target_36.getTarget().getName()="width"
		and target_36.getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_36.getParent().(AssignExpr).getRValue() = target_36
		and target_36.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_37(Parameter vcrop_5214, PointerFieldAccess target_37) {
		target_37.getTarget().getName()="length"
		and target_37.getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_37.getParent().(AssignExpr).getRValue() = target_37
		and target_37.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_38(Variable vscale_5217, Parameter vcrop_5214, Parameter vimage_5214, MulExpr target_38) {
		target_38.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_38.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_38.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_38.getRightOperand().(PointerFieldAccess).getTarget().getName()="xres"
		and target_38.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5214
		and target_38.getParent().(AssignExpr).getRValue() = target_38
		and target_38.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_39(Variable vscale_5217, Parameter vcrop_5214, Parameter vimage_5214, MulExpr target_39) {
		target_39.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="length"
		and target_39.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_39.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vscale_5217
		and target_39.getRightOperand().(PointerFieldAccess).getTarget().getName()="yres"
		and target_39.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_5214
		and target_39.getParent().(AssignExpr).getRValue() = target_39
		and target_39.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("uint32_t")
}

predicate func_40(Parameter vcrop_5214, BitwiseAndExpr target_40) {
		target_40.getLeftOperand().(PointerFieldAccess).getTarget().getName()="crop_mode"
		and target_40.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_40.getRightOperand().(Literal).getValue()="2"
}

predicate func_41(Parameter vcrop_5214, BitwiseAndExpr target_41) {
		target_41.getLeftOperand().(PointerFieldAccess).getTarget().getName()="crop_mode"
		and target_41.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_41.getRightOperand().(Literal).getValue()="4"
}

predicate func_42(Parameter vcrop_5214, BitwiseAndExpr target_42) {
		target_42.getLeftOperand().(PointerFieldAccess).getTarget().getName()="crop_mode"
		and target_42.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_5214
		and target_42.getRightOperand().(Literal).getValue()="2"
}

from Function func, Variable vi_5225, Variable vscale_5217, Variable vxres_5218, Variable vyres_5218, Parameter vcrop_5214, Parameter vimage_5214, MulExpr target_20, MulExpr target_21, MulExpr target_22, MulExpr target_23, ValueFieldAccess target_24, ValueFieldAccess target_25, ValueFieldAccess target_26, ValueFieldAccess target_27, ArrayExpr target_28, ArrayExpr target_29, ArrayExpr target_30, ArrayExpr target_31, MulExpr target_32, MulExpr target_33, MulExpr target_34, MulExpr target_35, PointerFieldAccess target_36, PointerFieldAccess target_37, MulExpr target_38, MulExpr target_39, BitwiseAndExpr target_40, BitwiseAndExpr target_41, BitwiseAndExpr target_42
where
not func_0(func)
and not func_1(func)
and not func_2(func)
and not func_3(func)
and not func_4(func)
and not func_5(func)
and not func_6(func)
and not func_7(func)
and not func_8(func)
and not func_9(func)
and not func_10(func)
and not func_11(func)
and not func_12(func)
and not func_13(func)
and not func_14(func)
and not func_15(func)
and not func_16(vcrop_5214, target_40, target_41)
and not func_17(vcrop_5214, target_41, target_42)
and not func_18(func)
and not func_19(func)
and func_20(vi_5225, vscale_5217, vxres_5218, vcrop_5214, target_20)
and func_21(vi_5225, vscale_5217, vxres_5218, vcrop_5214, target_21)
and func_22(vi_5225, vscale_5217, vyres_5218, vcrop_5214, target_22)
and func_23(vi_5225, vscale_5217, vyres_5218, vcrop_5214, target_23)
and func_24(vi_5225, vcrop_5214, target_24)
and func_25(vi_5225, vcrop_5214, target_25)
and func_26(vi_5225, vcrop_5214, target_26)
and func_27(vi_5225, vcrop_5214, target_27)
and func_28(vcrop_5214, target_28)
and func_29(vcrop_5214, target_29)
and func_30(vcrop_5214, target_30)
and func_31(vcrop_5214, target_31)
and func_32(vscale_5217, vyres_5218, vcrop_5214, target_32)
and func_33(vscale_5217, vxres_5218, vcrop_5214, target_33)
and func_34(vscale_5217, vyres_5218, vcrop_5214, target_34)
and func_35(vscale_5217, vxres_5218, vcrop_5214, target_35)
and func_36(vcrop_5214, target_36)
and func_37(vcrop_5214, target_37)
and func_38(vscale_5217, vcrop_5214, vimage_5214, target_38)
and func_39(vscale_5217, vcrop_5214, vimage_5214, target_39)
and func_40(vcrop_5214, target_40)
and func_41(vcrop_5214, target_41)
and func_42(vcrop_5214, target_42)
and vi_5225.getType().hasName("uint32_t")
and vscale_5217.getType().hasName("double")
and vxres_5218.getType().hasName("float")
and vyres_5218.getType().hasName("float")
and vcrop_5214.getType().hasName("crop_mask *")
and vimage_5214.getType().hasName("image_data *")
and vi_5225.(LocalVariable).getFunction() = func
and vscale_5217.(LocalVariable).getFunction() = func
and vxres_5218.(LocalVariable).getFunction() = func
and vyres_5218.(LocalVariable).getFunction() = func
and vcrop_5214.getFunction() = func
and vimage_5214.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
