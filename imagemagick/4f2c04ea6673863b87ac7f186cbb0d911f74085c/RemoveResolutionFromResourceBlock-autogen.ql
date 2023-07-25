/**
 * @name imagemagick-4f2c04ea6673863b87ac7f186cbb0d911f74085c-RemoveResolutionFromResourceBlock
 * @id cpp/imagemagick/4f2c04ea6673863b87ac7f186cbb0d911f74085c/RemoveResolutionFromResourceBlock
 * @description imagemagick-4f2c04ea6673863b87ac7f186cbb0d911f74085c-coders/psd.c-RemoveResolutionFromResourceBlock CVE-2016-7532
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(AddExpr).getParent().(BitwiseAndExpr).getLeftOperand() instanceof AddExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(EqualityOperation target_16, Function func) {
	exists(ReturnStmt target_1 |
		target_1.toString() = "return ..."
		and target_1.getParent().(IfStmt).getCondition()=target_16
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("ssize_t")
		and target_2.getRValue() instanceof BitwiseAndExpr
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(BlockStmt target_17, Function func) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_3.getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen()=target_17
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(LogicalAndExpr target_18, Function func) {
	exists(ReturnStmt target_4 |
		target_4.toString() = "return ..."
		and target_4.getParent().(IfStmt).getCondition()=target_18
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vbim_profile_2580, Variable vlength_2586, Variable vdatum_2589, Variable vid_2596, Variable vq_2606, ExprStmt target_19, LogicalAndExpr target_20, AddressOfExpr target_21, ExprStmt target_22) {
	exists(IfStmt target_5 |
		target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vid_2596
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="1005"
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_2586
		and target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="12"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CopyMagickMemory")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_2606
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vq_2606
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="12"
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_2586
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_2606
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdatum_2589
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("SetStringInfoLength")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbim_profile_2580
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_2586
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_5.getThen().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_20.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_21.getOperand().(VariableAccess).getLocation().isBefore(target_5.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_9(Parameter vbim_profile_2580, Variable vlength_2586, LogicalAndExpr target_18, ExprStmt target_19, SubExpr target_23) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("SetStringInfoLength")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbim_profile_2580
		and target_9.getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_2586
		and target_9.getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_9.getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_23.getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getLocation()))
}

*/
predicate func_11(Variable vcount_2592, BitwiseAndExpr target_11) {
		target_11.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_2592
		and target_11.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_11.getRightOperand().(UnaryMinusExpr).getValue()="-2"
}

predicate func_12(EqualityOperation target_16, Function func, BreakStmt target_12) {
		target_12.toString() = "break;"
		and target_12.getParent().(IfStmt).getCondition()=target_16
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Variable vcount_2592, LogicalAndExpr target_18, SubExpr target_23, BitwiseAndExpr target_13) {
		target_13.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_2592
		and target_13.getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_13.getRightOperand().(UnaryMinusExpr).getValue()="-2"
}

predicate func_14(Variable vcount_2592, BitwiseAndExpr target_14) {
		target_14.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_2592
		and target_14.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_14.getRightOperand().(UnaryMinusExpr).getValue()="-2"
}

predicate func_15(Variable vcount_2592, SubExpr target_23, ExprStmt target_26, BitwiseAndExpr target_15) {
		target_15.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcount_2592
		and target_15.getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_15.getRightOperand().(UnaryMinusExpr).getValue()="-2"
		and target_15.getLeftOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_26.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation())
}

predicate func_16(EqualityOperation target_16) {
		target_16.getAnOperand().(FunctionCall).getTarget().hasName("LocaleNCompare")
		and target_16.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="8BIM"
		and target_16.getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_16.getAnOperand().(Literal).getValue()="0"
}

predicate func_17(Variable vlength_2586, Variable vdatum_2589, Variable vq_2606, BlockStmt target_17) {
		target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CopyMagickMemory")
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vq_2606
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vq_2606
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="12"
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_2586
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand() instanceof BitwiseAndExpr
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_2606
		and target_17.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdatum_2589
}

predicate func_18(Variable vlength_2586, Variable vid_2596, LogicalAndExpr target_18) {
		target_18.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vid_2596
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(HexLiteral).getValue()="1005"
		and target_18.getAnOperand().(RelationalOperation).getLesserOperand() instanceof BitwiseAndExpr
		and target_18.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_2586
		and target_18.getAnOperand().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="12"
}

predicate func_19(Parameter vbim_profile_2580, Variable vdatum_2589, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdatum_2589
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetStringInfoDatum")
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbim_profile_2580
}

predicate func_20(Variable vlength_2586, Variable vdatum_2589, LogicalAndExpr target_20) {
		target_20.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdatum_2589
		and target_20.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdatum_2589
		and target_20.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_2586
		and target_20.getAnOperand().(RelationalOperation).getGreaterOperand().(PointerArithmeticOperation).getRightOperand().(Literal).getValue()="16"
}

predicate func_21(Variable vid_2596, AddressOfExpr target_21) {
		target_21.getOperand().(VariableAccess).getTarget()=vid_2596
}

predicate func_22(Variable vq_2606, ExprStmt target_22) {
		target_22.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vq_2606
}

predicate func_23(Variable vlength_2586, Variable vdatum_2589, Variable vq_2606, SubExpr target_23) {
		target_23.getLeftOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_2586
		and target_23.getLeftOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand() instanceof BitwiseAndExpr
		and target_23.getLeftOperand().(SubExpr).getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="12"
		and target_23.getRightOperand().(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vq_2606
		and target_23.getRightOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vdatum_2589
}

predicate func_26(Variable vcount_2592, ExprStmt target_26) {
		target_26.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vcount_2592
}

from Function func, Parameter vbim_profile_2580, Variable vlength_2586, Variable vdatum_2589, Variable vcount_2592, Variable vid_2596, Variable vq_2606, Literal target_0, BitwiseAndExpr target_11, BreakStmt target_12, BitwiseAndExpr target_13, BitwiseAndExpr target_14, BitwiseAndExpr target_15, EqualityOperation target_16, BlockStmt target_17, LogicalAndExpr target_18, ExprStmt target_19, LogicalAndExpr target_20, AddressOfExpr target_21, ExprStmt target_22, SubExpr target_23, ExprStmt target_26
where
func_0(func, target_0)
and not func_1(target_16, func)
and not func_2(func)
and not func_3(target_17, func)
and not func_4(target_18, func)
and not func_5(vbim_profile_2580, vlength_2586, vdatum_2589, vid_2596, vq_2606, target_19, target_20, target_21, target_22)
and func_11(vcount_2592, target_11)
and func_12(target_16, func, target_12)
and func_13(vcount_2592, target_18, target_23, target_13)
and func_14(vcount_2592, target_14)
and func_15(vcount_2592, target_23, target_26, target_15)
and func_16(target_16)
and func_17(vlength_2586, vdatum_2589, vq_2606, target_17)
and func_18(vlength_2586, vid_2596, target_18)
and func_19(vbim_profile_2580, vdatum_2589, target_19)
and func_20(vlength_2586, vdatum_2589, target_20)
and func_21(vid_2596, target_21)
and func_22(vq_2606, target_22)
and func_23(vlength_2586, vdatum_2589, vq_2606, target_23)
and func_26(vcount_2592, target_26)
and vbim_profile_2580.getType().hasName("StringInfo *")
and vlength_2586.getType().hasName("size_t")
and vdatum_2589.getType().hasName("unsigned char *")
and vcount_2592.getType().hasName("unsigned int")
and vid_2596.getType().hasName("unsigned short")
and vq_2606.getType().hasName("unsigned char *")
and vbim_profile_2580.getParentScope+() = func
and vlength_2586.getParentScope+() = func
and vdatum_2589.getParentScope+() = func
and vcount_2592.getParentScope+() = func
and vid_2596.getParentScope+() = func
and vq_2606.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
