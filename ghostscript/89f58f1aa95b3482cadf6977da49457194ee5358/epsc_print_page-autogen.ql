/**
 * @name ghostscript-89f58f1aa95b3482cadf6977da49457194ee5358-epsc_print_page
 * @id cpp/ghostscript/89f58f1aa95b3482cadf6977da49457194ee5358/epsc-print-page
 * @description ghostscript-89f58f1aa95b3482cadf6977da49457194ee5358-devices/gdevepsc.c-epsc_print_page CVE-2020-16294
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Initializer target_0) {
		target_0.getExpr() instanceof ExprCall
		and target_0.getExpr().getEnclosingFunction() = func
}

predicate func_1(Variable vy_24pin_173, ConditionalExpr target_29, ArrayExpr target_14) {
	exists(SubExpr target_1 |
		target_1.getLeftOperand().(MulExpr).getLeftOperand().(Literal).getValue()="60"
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vy_24pin_173
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(DivExpr).getValue()="7"
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getElse().(DivExpr).getValue()="5"
		and target_1.getRightOperand().(Literal).getValue()="1"
		and target_29.getCondition().(VariableAccess).getLocation().isBefore(target_1.getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getCondition().(VariableAccess).getLocation())
		and target_1.getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getCondition().(VariableAccess).getLocation().isBefore(target_14.getArrayBase().(ConditionalExpr).getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vx_dpi_184, DivExpr target_17, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vx_dpi_184
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_2)
		and target_17.getLeftOperand().(VariableAccess).getLocation().isBefore(target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vin_177, LogicalOrExpr target_30, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vin_177
		and target_3.getExpr().(AssignExpr).getRValue() instanceof ExprCall
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_3)
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_30.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vout_181, LogicalOrExpr target_30, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vout_181
		and target_4.getExpr().(AssignExpr).getRValue() instanceof ExprCall
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_4)
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_30.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vstart_graphics_185, ConditionalExpr target_15, ExprStmt target_31, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstart_graphics_185
		and target_5.getExpr().(AssignExpr).getRValue() instanceof ArrayExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_5)
		and target_15.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_31.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation()))
}

predicate func_6(Variable vfirst_pass_187, MulExpr target_16, ExprStmt target_32, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfirst_pass_187
		and target_6.getExpr().(AssignExpr).getRValue() instanceof ConditionalExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_6)
		and target_16.getLeftOperand().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_32.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_7(Variable vlast_pass_188, RelationalOperation target_33, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlast_pass_188
		and target_7.getExpr().(AssignExpr).getRValue() instanceof MulExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(26)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(26).getFollowingStmt()=target_7)
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_33.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vdots_per_space_189, MulExpr target_18, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdots_per_space_189
		and target_8.getExpr().(AssignExpr).getRValue() instanceof DivExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(27)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(27).getFollowingStmt()=target_8)
		and target_18.getLeftOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_9(Variable vbytes_per_space_190, ExprStmt target_34, Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_per_space_190
		and target_9.getExpr().(AssignExpr).getRValue() instanceof MulExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(28)=target_9 or func.getEntryPoint().(BlockStmt).getStmt(28).getFollowingStmt()=target_9)
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_34.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getLocation()))
}

predicate func_10(Variable vspare_bits_196, SubExpr target_20, LogicalAndExpr target_35, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vspare_bits_196
		and target_10.getExpr().(AssignExpr).getRValue() instanceof RemExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(29)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(29).getFollowingStmt()=target_10)
		and target_20.getRightOperand().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_35.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_11(Variable vwhole_bits_197, Function func) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vwhole_bits_197
		and target_11.getExpr().(AssignExpr).getRValue() instanceof SubExpr
		and (func.getEntryPoint().(BlockStmt).getStmt(30)=target_11 or func.getEntryPoint().(BlockStmt).getStmt(30).getFollowingStmt()=target_11))
}

predicate func_12(Parameter vpdev_165, Variable vin_size_176, ExprCall target_12) {
		target_12.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_byte_array"
		and target_12.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_12.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_12.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_12.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_165
		and target_12.getArgument(0).(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_12.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_12.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_165
		and target_12.getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vin_size_176
		and target_12.getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_12.getArgument(2).(Literal).getValue()="1"
		and target_12.getArgument(3).(StringLiteral).getValue()="epsc_print_page(in)"
}

predicate func_13(Parameter vpdev_165, Variable vout_size_180, ExprCall target_13) {
		target_13.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="alloc_byte_array"
		and target_13.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="procs"
		and target_13.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_13.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_13.getExpr().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_165
		and target_13.getArgument(0).(PointerFieldAccess).getTarget().getName()="non_gc_memory"
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_13.getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_165
		and target_13.getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vout_size_180
		and target_13.getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_13.getArgument(2).(Literal).getValue()="1"
		and target_13.getArgument(3).(StringLiteral).getValue()="epsc_print_page(out)"
}

predicate func_14(Variable vgraphics_modes_9_167, Variable vgraphics_modes_24_169, Variable vy_24pin_173, Variable vx_dpi_184, ArrayExpr target_14) {
		target_14.getArrayBase().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vy_24pin_173
		and target_14.getArrayBase().(ConditionalExpr).getThen().(VariableAccess).getTarget()=vgraphics_modes_24_169
		and target_14.getArrayBase().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vgraphics_modes_9_167
		and target_14.getArrayOffset().(DivExpr).getLeftOperand().(VariableAccess).getTarget()=vx_dpi_184
		and target_14.getArrayOffset().(DivExpr).getRightOperand().(Literal).getValue()="60"
}

predicate func_15(Variable vstart_graphics_185, ConditionalExpr target_15) {
		target_15.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vstart_graphics_185
		and target_15.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="128"
		and target_15.getThen().(Literal).getValue()="1"
		and target_15.getElse().(Literal).getValue()="0"
}

predicate func_16(Variable vfirst_pass_187, MulExpr target_16) {
		target_16.getLeftOperand().(VariableAccess).getTarget()=vfirst_pass_187
		and target_16.getRightOperand().(Literal).getValue()="2"
}

predicate func_17(Variable vx_dpi_184, DivExpr target_17) {
		target_17.getLeftOperand().(VariableAccess).getTarget()=vx_dpi_184
		and target_17.getRightOperand().(Literal).getValue()="10"
}

predicate func_18(Variable vy_mult_174, Variable vdots_per_space_189, MulExpr target_18) {
		target_18.getLeftOperand().(VariableAccess).getTarget()=vdots_per_space_189
		and target_18.getRightOperand().(VariableAccess).getTarget()=vy_mult_174
}

predicate func_19(Parameter vpdev_165, RemExpr target_19) {
		target_19.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_19.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_165
		and target_19.getRightOperand().(Literal).getValue()="8"
}

predicate func_20(Parameter vpdev_165, Variable vspare_bits_196, SubExpr target_20) {
		target_20.getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_20.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpdev_165
		and target_20.getRightOperand().(VariableAccess).getTarget()=vspare_bits_196
}

predicate func_21(Function func, Initializer target_21) {
		target_21.getExpr() instanceof ExprCall
		and target_21.getExpr().getEnclosingFunction() = func
}

predicate func_22(Function func, Initializer target_22) {
		target_22.getExpr() instanceof ArrayExpr
		and target_22.getExpr().getEnclosingFunction() = func
}

predicate func_23(Function func, Initializer target_23) {
		target_23.getExpr() instanceof ConditionalExpr
		and target_23.getExpr().getEnclosingFunction() = func
}

predicate func_24(Function func, Initializer target_24) {
		target_24.getExpr() instanceof MulExpr
		and target_24.getExpr().getEnclosingFunction() = func
}

predicate func_25(Function func, Initializer target_25) {
		target_25.getExpr() instanceof DivExpr
		and target_25.getExpr().getEnclosingFunction() = func
}

predicate func_26(Function func, Initializer target_26) {
		target_26.getExpr() instanceof MulExpr
		and target_26.getExpr().getEnclosingFunction() = func
}

predicate func_27(Function func, Initializer target_27) {
		target_27.getExpr() instanceof RemExpr
		and target_27.getExpr().getEnclosingFunction() = func
}

predicate func_28(Function func, Initializer target_28) {
		target_28.getExpr() instanceof SubExpr
		and target_28.getExpr().getEnclosingFunction() = func
}

predicate func_29(Variable vy_24pin_173, ConditionalExpr target_29) {
		target_29.getCondition().(VariableAccess).getTarget()=vy_24pin_173
		and target_29.getThen().(Literal).getValue()="3"
		and target_29.getElse().(Literal).getValue()="1"
}

predicate func_30(Variable vin_177, Variable vout_181, LogicalOrExpr target_30) {
		target_30.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vin_177
		and target_30.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_30.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vout_181
		and target_30.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_31(Variable vy_mult_174, Variable vstart_graphics_185, ExprStmt target_31) {
		target_31.getExpr().(FunctionCall).getTarget().hasName("epsc_output_run")
		and target_31.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("byte *")
		and target_31.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_31.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_31.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vy_mult_174
		and target_31.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vstart_graphics_185
		and target_31.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("gp_file *")
		and target_31.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_32(Variable vfirst_pass_187, ExprStmt target_32) {
		target_32.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_32.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vfirst_pass_187
}

predicate func_33(Variable vlast_pass_188, RelationalOperation target_33) {
		 (target_33 instanceof GEExpr or target_33 instanceof LEExpr)
		and target_33.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_33.getGreaterOperand().(VariableAccess).getTarget()=vlast_pass_188
}

predicate func_34(Variable vout_181, Variable vbytes_per_space_190, ExprStmt target_34) {
		target_34.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_34.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("byte *")
		and target_34.getExpr().(AssignExpr).getRValue().(DivExpr).getLeftOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vout_181
		and target_34.getExpr().(AssignExpr).getRValue().(DivExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_per_space_190
}

predicate func_35(Variable vspare_bits_196, LogicalAndExpr target_35) {
		target_35.getAnOperand().(VariableAccess).getTarget()=vspare_bits_196
		and target_35.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_35.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vpdev_165, Variable vgraphics_modes_9_167, Variable vgraphics_modes_24_169, Variable vy_24pin_173, Variable vy_mult_174, Variable vin_size_176, Variable vin_177, Variable vout_size_180, Variable vout_181, Variable vx_dpi_184, Variable vstart_graphics_185, Variable vfirst_pass_187, Variable vlast_pass_188, Variable vdots_per_space_189, Variable vbytes_per_space_190, Variable vspare_bits_196, Variable vwhole_bits_197, Initializer target_0, ExprCall target_12, ExprCall target_13, ArrayExpr target_14, ConditionalExpr target_15, MulExpr target_16, DivExpr target_17, MulExpr target_18, RemExpr target_19, SubExpr target_20, Initializer target_21, Initializer target_22, Initializer target_23, Initializer target_24, Initializer target_25, Initializer target_26, Initializer target_27, Initializer target_28, ConditionalExpr target_29, LogicalOrExpr target_30, ExprStmt target_31, ExprStmt target_32, RelationalOperation target_33, ExprStmt target_34, LogicalAndExpr target_35
where
func_0(func, target_0)
and not func_1(vy_24pin_173, target_29, target_14)
and not func_2(vx_dpi_184, target_17, func)
and not func_3(vin_177, target_30, func)
and not func_4(vout_181, target_30, func)
and not func_5(vstart_graphics_185, target_15, target_31, func)
and not func_6(vfirst_pass_187, target_16, target_32, func)
and not func_7(vlast_pass_188, target_33, func)
and not func_8(vdots_per_space_189, target_18, func)
and not func_9(vbytes_per_space_190, target_34, func)
and not func_10(vspare_bits_196, target_20, target_35, func)
and not func_11(vwhole_bits_197, func)
and func_12(vpdev_165, vin_size_176, target_12)
and func_13(vpdev_165, vout_size_180, target_13)
and func_14(vgraphics_modes_9_167, vgraphics_modes_24_169, vy_24pin_173, vx_dpi_184, target_14)
and func_15(vstart_graphics_185, target_15)
and func_16(vfirst_pass_187, target_16)
and func_17(vx_dpi_184, target_17)
and func_18(vy_mult_174, vdots_per_space_189, target_18)
and func_19(vpdev_165, target_19)
and func_20(vpdev_165, vspare_bits_196, target_20)
and func_21(func, target_21)
and func_22(func, target_22)
and func_23(func, target_23)
and func_24(func, target_24)
and func_25(func, target_25)
and func_26(func, target_26)
and func_27(func, target_27)
and func_28(func, target_28)
and func_29(vy_24pin_173, target_29)
and func_30(vin_177, vout_181, target_30)
and func_31(vy_mult_174, vstart_graphics_185, target_31)
and func_32(vfirst_pass_187, target_32)
and func_33(vlast_pass_188, target_33)
and func_34(vout_181, vbytes_per_space_190, target_34)
and func_35(vspare_bits_196, target_35)
and vpdev_165.getType().hasName("gx_device_printer *")
and vgraphics_modes_9_167.getType().hasName("int[5]")
and vgraphics_modes_24_169.getType().hasName("int[7]")
and vy_24pin_173.getType().hasName("int")
and vy_mult_174.getType().hasName("int")
and vin_size_176.getType().hasName("int")
and vin_177.getType().hasName("byte *")
and vout_size_180.getType().hasName("int")
and vout_181.getType().hasName("byte *")
and vx_dpi_184.getType().hasName("int")
and vstart_graphics_185.getType().hasName("char")
and vfirst_pass_187.getType().hasName("int")
and vlast_pass_188.getType().hasName("int")
and vdots_per_space_189.getType().hasName("int")
and vbytes_per_space_190.getType().hasName("int")
and vspare_bits_196.getType().hasName("int")
and vwhole_bits_197.getType().hasName("int")
and vpdev_165.getFunction() = func
and vgraphics_modes_9_167.(LocalVariable).getFunction() = func
and vgraphics_modes_24_169.(LocalVariable).getFunction() = func
and vy_24pin_173.(LocalVariable).getFunction() = func
and vy_mult_174.(LocalVariable).getFunction() = func
and vin_size_176.(LocalVariable).getFunction() = func
and vin_177.(LocalVariable).getFunction() = func
and vout_size_180.(LocalVariable).getFunction() = func
and vout_181.(LocalVariable).getFunction() = func
and vx_dpi_184.(LocalVariable).getFunction() = func
and vstart_graphics_185.(LocalVariable).getFunction() = func
and vfirst_pass_187.(LocalVariable).getFunction() = func
and vlast_pass_188.(LocalVariable).getFunction() = func
and vdots_per_space_189.(LocalVariable).getFunction() = func
and vbytes_per_space_190.(LocalVariable).getFunction() = func
and vspare_bits_196.(LocalVariable).getFunction() = func
and vwhole_bits_197.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
