/**
 * @name openssl-578b956fe741bf8e84055547b1e83c28dd902c73-fmtfp
 * @id cpp/openssl/578b956fe741bf8e84055547b1e83c28dd902c73/fmtfp
 * @description openssl-578b956fe741bf8e84055547b1e83c28dd902c73-fmtfp CVE-2016-0799
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585, Variable vsignvalue_587) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue_587
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vsignvalue_587)
}

predicate func_1(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_2(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_5(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_5.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_6(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585, Parameter vmax_585, Parameter vflags_585) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_6.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_585
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_585
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="8")
}

predicate func_7(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585) {
	exists(IfStmt target_7 |
		target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_7.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_7.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_11(Variable viconvert_589, Variable viplace_591) {
	exists(ArrayExpr target_11 |
		target_11.getArrayBase().(VariableAccess).getTarget()=viconvert_589
		and target_11.getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=viplace_591
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_12(Variable vfconvert_590, Variable vfplace_592) {
	exists(ArrayExpr target_12 |
		target_12.getArrayBase().(VariableAccess).getTarget()=vfconvert_590
		and target_12.getArrayOffset().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vfplace_592
		and target_12.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_13(Variable vzpadlen_594) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(PrefixDecrExpr).getOperand().(VariableAccess).getTarget()=vzpadlen_594)
}

predicate func_14(Variable vpadlen_593) {
	exists(ExprStmt target_14 |
		target_14.getExpr().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vpadlen_593)
}

predicate func_24(Function func) {
	exists(CharLiteral target_24 |
		target_24.getValue()="48"
		and target_24.getEnclosingFunction() = func)
}

predicate func_29(Function func) {
	exists(CharLiteral target_29 |
		target_29.getValue()="32"
		and target_29.getEnclosingFunction() = func)
}

predicate func_43(Function func) {
	exists(CharLiteral target_43 |
		target_43.getValue()="46"
		and target_43.getEnclosingFunction() = func)
}

predicate func_59(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585, Variable vsignvalue_587) {
	exists(ExprStmt target_59 |
		target_59.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_59.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_59.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_59.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_59.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_59.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsignvalue_587
		and target_59.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=vsignvalue_587)
}

predicate func_60(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585) {
	exists(ExprStmt target_60 |
		target_60.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_60.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_60.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_60.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_60.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_60.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral)
}

predicate func_61(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585) {
	exists(ExprStmt target_61 |
		target_61.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_61.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_61.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_61.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_61.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_61.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral)
}

predicate func_63(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585, Variable viplace_591) {
	exists(ExprStmt target_63 |
		target_63.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_63.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_63.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_63.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_63.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_63.getExpr().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_63.getParent().(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=viplace_591
		and target_63.getParent().(WhileStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0")
}

predicate func_64(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585, Parameter vmax_585, Parameter vflags_585) {
	exists(ExprStmt target_64 |
		target_64.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_64.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_64.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_64.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_64.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_64.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_64.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmax_585
		and target_64.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_64.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_585
		and target_64.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="8")
}

predicate func_65(Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585, Variable vfplace_592) {
	exists(ExprStmt target_65 |
		target_65.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_65.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_582
		and target_65.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_583
		and target_65.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcurrlen_584
		and target_65.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_585
		and target_65.getExpr().(FunctionCall).getArgument(4) instanceof ArrayExpr
		and target_65.getParent().(WhileStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vfplace_592
		and target_65.getParent().(WhileStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0")
}

from Function func, Parameter vsbuffer_582, Parameter vbuffer_583, Parameter vcurrlen_584, Parameter vmaxlen_585, Parameter vmax_585, Parameter vflags_585, Variable vsignvalue_587, Variable viconvert_589, Variable vfconvert_590, Variable viplace_591, Variable vfplace_592, Variable vpadlen_593, Variable vzpadlen_594
where
not func_0(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585, vsignvalue_587)
and not func_1(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585)
and not func_2(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585)
and not func_5(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585)
and not func_6(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585, vmax_585, vflags_585)
and not func_7(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585)
and func_11(viconvert_589, viplace_591)
and func_12(vfconvert_590, vfplace_592)
and func_13(vzpadlen_594)
and func_14(vpadlen_593)
and func_24(func)
and func_29(func)
and func_43(func)
and func_59(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585, vsignvalue_587)
and func_60(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585)
and func_61(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585)
and func_63(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585, viplace_591)
and func_64(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585, vmax_585, vflags_585)
and func_65(vsbuffer_582, vbuffer_583, vcurrlen_584, vmaxlen_585, vfplace_592)
and vsbuffer_582.getType().hasName("char **")
and vbuffer_583.getType().hasName("char **")
and vcurrlen_584.getType().hasName("size_t *")
and vmaxlen_585.getType().hasName("size_t *")
and vmax_585.getType().hasName("int")
and vflags_585.getType().hasName("int")
and vsignvalue_587.getType().hasName("int")
and viconvert_589.getType().hasName("char[20]")
and vfconvert_590.getType().hasName("char[20]")
and viplace_591.getType().hasName("int")
and vfplace_592.getType().hasName("int")
and vpadlen_593.getType().hasName("int")
and vzpadlen_594.getType().hasName("int")
and vsbuffer_582.getParentScope+() = func
and vbuffer_583.getParentScope+() = func
and vcurrlen_584.getParentScope+() = func
and vmaxlen_585.getParentScope+() = func
and vmax_585.getParentScope+() = func
and vflags_585.getParentScope+() = func
and vsignvalue_587.getParentScope+() = func
and viconvert_589.getParentScope+() = func
and vfconvert_590.getParentScope+() = func
and viplace_591.getParentScope+() = func
and vfplace_592.getParentScope+() = func
and vpadlen_593.getParentScope+() = func
and vzpadlen_594.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
