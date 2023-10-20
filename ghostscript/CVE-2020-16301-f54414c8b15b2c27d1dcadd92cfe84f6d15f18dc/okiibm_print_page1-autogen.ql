/**
 * @name ghostscript-f54414c8b15b2c27d1dcadd92cfe84f6d15f18dc-okiibm_print_page1
 * @id cpp/ghostscript/f54414c8b15b2c27d1dcadd92cfe84f6d15f18dc/okiibm-print-page1
 * @description ghostscript-f54414c8b15b2c27d1dcadd92cfe84f6d15f18dc-devices/gdevokii.c-okiibm_print_page1 CVE-2020-16301
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vx_dpi_108, ArrayExpr target_21, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vx_dpi_108
		and target_0.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_0)
		and target_21.getArrayOffset().(DivExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vx_dpi_108, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vx_dpi_108
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="60"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="5"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_1))
}

predicate func_2(Variable vin_y_mult_99, MulExpr target_17, ExprStmt target_41, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vin_y_mult_99
		and target_2.getExpr().(AssignExpr).getRValue() instanceof ConditionalExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(18)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(18).getFollowingStmt()=target_2)
		and target_17.getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_41.getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vline_size_100, MulExpr target_17, SubExpr target_42, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vline_size_100
		and target_3.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_3)
		and target_17.getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_42.getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vin_size_102, ExprCall target_19, ExprStmt target_43, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vin_size_102
		and target_4.getExpr().(AssignExpr).getRValue() instanceof MulExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_4)
		and target_19.getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_5(Variable vbuf1_103, LogicalOrExpr target_44, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf1_103
		and target_5.getExpr().(AssignExpr).getRValue() instanceof ExprCall
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_5)
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_44.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_6(Variable vbuf2_104, LogicalOrExpr target_44, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf2_104
		and target_6.getExpr().(AssignExpr).getRValue() instanceof ExprCall
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_6)
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_44.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_7(Variable vbuf1_103, Variable vin_105, ExprStmt target_45, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vin_105
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuf1_103
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_7)
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_45.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_8(Variable vbuf2_104, Variable vout_106, PointerArithmeticOperation target_46, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vout_106
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vbuf2_104
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_8)
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_46.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_9(Variable vout_y_mult_107, ExprStmt target_47, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vout_y_mult_107
		and target_9.getExpr().(AssignExpr).getRValue() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_9)
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_47.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_10(Variable vstart_graphics_109, ConditionalExpr target_22, ExprStmt target_47, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_graphics_109
		and target_10.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_10)
		and target_22.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_47.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_11(Variable vfirst_pass_110, MulExpr target_23, ExprStmt target_48, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfirst_pass_110
		and target_11.getExpr().(AssignExpr).getRValue() instanceof ConditionalExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_11)
		and target_23.getLeftOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_48.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_12(Variable vlast_pass_111, RelationalOperation target_49, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlast_pass_111
		and target_12.getExpr().(AssignExpr).getRValue() instanceof MulExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_12)
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_49.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_13(Variable vy_passes_112, RelationalOperation target_50, Function func) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_passes_112
		and target_13.getExpr().(AssignExpr).getRValue() instanceof ConditionalExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_13 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_13)
		and target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_50.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_14(Variable vy_step_114, AddExpr target_51, Function func) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vy_step_114
		and target_14.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(30)=target_14 or func.getEntryPoint().(BlockStmt).getStmt(30).getFollowingStmt()=target_14)
		and target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_51.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_15(Parameter vy_9pin_high_90, ConditionalExpr target_15) {
		target_15.getCondition().(VariableAccess).getTarget()=vy_9pin_high_90
		and target_15.getThen().(Literal).getValue()="2"
		and target_15.getElse().(Literal).getValue()="1"
}

predicate func_16(Parameter vpdev_90, FunctionCall target_16) {
		target_16.getTarget().hasName("gx_device_raster")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vpdev_90
		and target_16.getArgument(1).(Literal).getValue()="0"
}

predicate func_17(Variable vin_y_mult_99, Variable vline_size_100, MulExpr target_17) {
		target_17.getLeftOperand().(VariableAccess).getTarget()=vline_size_100
		and target_17.getRightOperand().(MulExpr).getLeftOperand().(Literal).getValue()="8"
		and target_17.getRightOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vin_y_mult_99
}

predicate func_18(Parameter vpdev_90, Variable vin_size_102, ExprCall target_18) {
		target_18.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_byte_array"
		and target_18.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_18.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_18.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_18.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_90
		and target_18.getArgument(0).(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_18.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_18.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_90
		and target_18.getArgument(1).(VariableAccess).getTarget()=vin_size_102
		and target_18.getArgument(2).(Literal).getValue()="1"
		and target_18.getArgument(3).(StringLiteral).getValue()="okiibm_print_page(buf1)"
}

predicate func_19(Parameter vpdev_90, Variable vin_size_102, ExprCall target_19) {
		target_19.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_byte_array"
		and target_19.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_19.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_19.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_19.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_90
		and target_19.getArgument(0).(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_19.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_19.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_90
		and target_19.getArgument(1).(VariableAccess).getTarget()=vin_size_102
		and target_19.getArgument(2).(Literal).getValue()="1"
		and target_19.getArgument(3).(StringLiteral).getValue()="okiibm_print_page(buf2)"
}

predicate func_20(Parameter vpdev_90, ArrayExpr target_20) {
		target_20.getArrayBase().(PointerFieldAccess).getTarget().getName()="HWResolution"
		and target_20.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_90
		and target_20.getArrayOffset().(Literal).getValue()="0"
}

predicate func_21(Variable vgraphics_modes_9_94, Variable vx_dpi_108, ArrayExpr target_21) {
		target_21.getArrayBase().(VariableAccess).getTarget()=vgraphics_modes_9_94
		and target_21.getArrayOffset().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vx_dpi_108
		and target_21.getArrayOffset().(DivExpr).getRightOperand().(Literal).getValue()="60"
}

predicate func_22(Variable vstart_graphics_109, ConditionalExpr target_22) {
		target_22.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstart_graphics_109
		and target_22.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_22.getThen().(Literal).getValue()="1"
		and target_22.getElse().(Literal).getValue()="0"
}

predicate func_23(Variable vfirst_pass_110, MulExpr target_23) {
		target_23.getLeftOperand().(VariableAccess).getTarget()=vfirst_pass_110
		and target_23.getRightOperand().(Literal).getValue()="2"
}

predicate func_24(Parameter vy_9pin_high_90, ConditionalExpr target_24) {
		target_24.getCondition().(VariableAccess).getTarget()=vy_9pin_high_90
		and target_24.getThen().(Literal).getValue()="2"
		and target_24.getElse().(Literal).getValue()="1"
}

predicate func_25(Variable vbuf1_103, VariableAccess target_25) {
		target_25.getTarget()=vbuf1_103
}

predicate func_26(Variable vbuf2_104, VariableAccess target_26) {
		target_26.getTarget()=vbuf2_104
}

predicate func_28(Function func, Initializer target_28) {
		target_28.getExpr() instanceof ConditionalExpr
		and target_28.getExpr().getEnclosingFunction() = func
}

predicate func_29(Function func, Initializer target_29) {
		target_29.getExpr() instanceof FunctionCall
		and target_29.getExpr().getEnclosingFunction() = func
}

predicate func_30(Function func, Initializer target_30) {
		target_30.getExpr() instanceof MulExpr
		and target_30.getExpr().getEnclosingFunction() = func
}

predicate func_31(Function func, Initializer target_31) {
		target_31.getExpr() instanceof ExprCall
		and target_31.getExpr().getEnclosingFunction() = func
}

predicate func_32(Function func, Initializer target_32) {
		target_32.getExpr() instanceof ExprCall
		and target_32.getExpr().getEnclosingFunction() = func
}

predicate func_33(Variable vbuf1_103, Initializer target_33) {
		target_33.getExpr().(VariableAccess).getTarget()=vbuf1_103
}

predicate func_34(Variable vbuf2_104, Initializer target_34) {
		target_34.getExpr().(VariableAccess).getTarget()=vbuf2_104
}

predicate func_35(Function func, Initializer target_35) {
		target_35.getExpr() instanceof Literal
		and target_35.getExpr().getEnclosingFunction() = func
}

predicate func_36(Function func, Initializer target_36) {
		target_36.getExpr() instanceof ArrayExpr
		and target_36.getExpr().getEnclosingFunction() = func
}

predicate func_37(Function func, Initializer target_37) {
		target_37.getExpr() instanceof ArrayExpr
		and target_37.getExpr().getEnclosingFunction() = func
}

predicate func_38(Function func, Initializer target_38) {
		target_38.getExpr() instanceof ConditionalExpr
		and target_38.getExpr().getEnclosingFunction() = func
}

predicate func_39(Function func, Initializer target_39) {
		target_39.getExpr() instanceof MulExpr
		and target_39.getExpr().getEnclosingFunction() = func
}

predicate func_40(Function func, Initializer target_40) {
		target_40.getExpr() instanceof ConditionalExpr
		and target_40.getExpr().getEnclosingFunction() = func
}

predicate func_41(Variable vin_y_mult_99, ExprStmt target_41) {
		target_41.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_41.getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(Literal).getValue()="2"
		and target_41.getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vin_y_mult_99
}

predicate func_42(Variable vline_size_100, SubExpr target_42) {
		target_42.getLeftOperand().(VariableAccess).getTarget()=vline_size_100
		and target_42.getRightOperand().(Literal).getValue()="1"
}

predicate func_43(Parameter vpdev_90, Variable vin_size_102, Variable vin_105, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("gdev_prn_copy_scan_lines")
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_90
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vin_105
		and target_43.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vin_size_102
}

predicate func_44(Variable vbuf1_103, Variable vbuf2_104, LogicalOrExpr target_44) {
		target_44.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf1_103
		and target_44.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_44.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbuf2_104
		and target_44.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_45(Parameter vpdev_90, Variable vin_105, ExprStmt target_45) {
		target_45.getExpr().(FunctionCall).getTarget().hasName("gdev_prn_get_bits")
		and target_45.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_90
		and target_45.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
		and target_45.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vin_105
		and target_45.getExpr().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("byte *")
}

predicate func_46(Variable vline_size_100, Variable vout_106, PointerArithmeticOperation target_46) {
		target_46.getAnOperand().(VariableAccess).getTarget()=vout_106
		and target_46.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_46.getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vline_size_100
}

predicate func_47(Variable vout_106, Variable vout_y_mult_107, Variable vstart_graphics_109, ExprStmt target_47) {
		target_47.getExpr().(FunctionCall).getTarget().hasName("okiibm_output_run")
		and target_47.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vout_106
		and target_47.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_47.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vout_106
		and target_47.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vout_y_mult_107
		and target_47.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vstart_graphics_109
		and target_47.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("gp_file *")
		and target_47.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_48(Variable vfirst_pass_110, ExprStmt target_48) {
		target_48.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_48.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vfirst_pass_110
}

predicate func_49(Variable vlast_pass_111, RelationalOperation target_49) {
		 (target_49 instanceof GEExpr or target_49 instanceof LEExpr)
		and target_49.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_49.getGreaterOperand().(VariableAccess).getTarget()=vlast_pass_111
}

predicate func_50(Variable vy_passes_112, RelationalOperation target_50) {
		 (target_50 instanceof GTExpr or target_50 instanceof LTExpr)
		and target_50.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_50.getGreaterOperand().(VariableAccess).getTarget()=vy_passes_112
}

predicate func_51(Variable vy_step_114, AddExpr target_51) {
		target_51.getAnOperand().(Literal).getValue()="1"
		and target_51.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vy_step_114
		and target_51.getAnOperand().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_51.getAnOperand().(ConditionalExpr).getThen().(Literal).getValue()="1"
		and target_51.getAnOperand().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

from Function func, Parameter vpdev_90, Parameter vy_9pin_high_90, Variable vgraphics_modes_9_94, Variable vin_y_mult_99, Variable vline_size_100, Variable vin_size_102, Variable vbuf1_103, Variable vbuf2_104, Variable vin_105, Variable vout_106, Variable vout_y_mult_107, Variable vx_dpi_108, Variable vstart_graphics_109, Variable vfirst_pass_110, Variable vlast_pass_111, Variable vy_passes_112, Variable vy_step_114, ConditionalExpr target_15, FunctionCall target_16, MulExpr target_17, ExprCall target_18, ExprCall target_19, ArrayExpr target_20, ArrayExpr target_21, ConditionalExpr target_22, MulExpr target_23, ConditionalExpr target_24, VariableAccess target_25, VariableAccess target_26, Initializer target_28, Initializer target_29, Initializer target_30, Initializer target_31, Initializer target_32, Initializer target_33, Initializer target_34, Initializer target_35, Initializer target_36, Initializer target_37, Initializer target_38, Initializer target_39, Initializer target_40, ExprStmt target_41, SubExpr target_42, ExprStmt target_43, LogicalOrExpr target_44, ExprStmt target_45, PointerArithmeticOperation target_46, ExprStmt target_47, ExprStmt target_48, RelationalOperation target_49, RelationalOperation target_50, AddExpr target_51
where
not func_0(vx_dpi_108, target_21, func)
and not func_1(vx_dpi_108, func)
and not func_2(vin_y_mult_99, target_17, target_41, func)
and not func_3(vline_size_100, target_17, target_42, func)
and not func_4(vin_size_102, target_19, target_43, func)
and not func_5(vbuf1_103, target_44, func)
and not func_6(vbuf2_104, target_44, func)
and not func_7(vbuf1_103, vin_105, target_45, func)
and not func_8(vbuf2_104, vout_106, target_46, func)
and not func_9(vout_y_mult_107, target_47, func)
and not func_10(vstart_graphics_109, target_22, target_47, func)
and not func_11(vfirst_pass_110, target_23, target_48, func)
and not func_12(vlast_pass_111, target_49, func)
and not func_13(vy_passes_112, target_50, func)
and not func_14(vy_step_114, target_51, func)
and func_15(vy_9pin_high_90, target_15)
and func_16(vpdev_90, target_16)
and func_17(vin_y_mult_99, vline_size_100, target_17)
and func_18(vpdev_90, vin_size_102, target_18)
and func_19(vpdev_90, vin_size_102, target_19)
and func_20(vpdev_90, target_20)
and func_21(vgraphics_modes_9_94, vx_dpi_108, target_21)
and func_22(vstart_graphics_109, target_22)
and func_23(vfirst_pass_110, target_23)
and func_24(vy_9pin_high_90, target_24)
and func_25(vbuf1_103, target_25)
and func_26(vbuf2_104, target_26)
and func_28(func, target_28)
and func_29(func, target_29)
and func_30(func, target_30)
and func_31(func, target_31)
and func_32(func, target_32)
and func_33(vbuf1_103, target_33)
and func_34(vbuf2_104, target_34)
and func_35(func, target_35)
and func_36(func, target_36)
and func_37(func, target_37)
and func_38(func, target_38)
and func_39(func, target_39)
and func_40(func, target_40)
and func_41(vin_y_mult_99, target_41)
and func_42(vline_size_100, target_42)
and func_43(vpdev_90, vin_size_102, vin_105, target_43)
and func_44(vbuf1_103, vbuf2_104, target_44)
and func_45(vpdev_90, vin_105, target_45)
and func_46(vline_size_100, vout_106, target_46)
and func_47(vout_106, vout_y_mult_107, vstart_graphics_109, target_47)
and func_48(vfirst_pass_110, target_48)
and func_49(vlast_pass_111, target_49)
and func_50(vy_passes_112, target_50)
and func_51(vy_step_114, target_51)
and vpdev_90.getType().hasName("gx_device_printer *")
and vy_9pin_high_90.getType().hasName("int")
and vgraphics_modes_9_94.getType().hasName("const char[5]")
and vin_y_mult_99.getType().hasName("int")
and vline_size_100.getType().hasName("int")
and vin_size_102.getType().hasName("int")
and vbuf1_103.getType().hasName("byte *")
and vbuf2_104.getType().hasName("byte *")
and vin_105.getType().hasName("byte *")
and vout_106.getType().hasName("byte *")
and vout_y_mult_107.getType().hasName("int")
and vx_dpi_108.getType().hasName("int")
and vstart_graphics_109.getType().hasName("char")
and vfirst_pass_110.getType().hasName("int")
and vlast_pass_111.getType().hasName("int")
and vy_passes_112.getType().hasName("int")
and vy_step_114.getType().hasName("int")
and vpdev_90.getFunction() = func
and vy_9pin_high_90.getFunction() = func
and vgraphics_modes_9_94.(LocalVariable).getFunction() = func
and vin_y_mult_99.(LocalVariable).getFunction() = func
and vline_size_100.(LocalVariable).getFunction() = func
and vin_size_102.(LocalVariable).getFunction() = func
and vbuf1_103.(LocalVariable).getFunction() = func
and vbuf2_104.(LocalVariable).getFunction() = func
and vin_105.(LocalVariable).getFunction() = func
and vout_106.(LocalVariable).getFunction() = func
and vout_y_mult_107.(LocalVariable).getFunction() = func
and vx_dpi_108.(LocalVariable).getFunction() = func
and vstart_graphics_109.(LocalVariable).getFunction() = func
and vfirst_pass_110.(LocalVariable).getFunction() = func
and vlast_pass_111.(LocalVariable).getFunction() = func
and vy_passes_112.(LocalVariable).getFunction() = func
and vy_step_114.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
