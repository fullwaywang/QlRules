/**
 * @name imagemagick-052f6c22d3a2b2aae9dfa24aff9ccdf8b72ace91-WriteTIFFImage
 * @id cpp/imagemagick/052f6c22d3a2b2aae9dfa24aff9ccdf8b72ace91/WriteTIFFImage
 * @description imagemagick-052f6c22d3a2b2aae9dfa24aff9ccdf8b72ace91-coders/tiff.c-WriteTIFFImage CVE-2018-10804
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_info_3387, Parameter vimage_3388, Parameter vexception_3388, Variable vstatus_3403, Variable vquantum_info_3409, Variable v__func__, LogicalAndExpr target_2, EqualityOperation target_3, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6, EqualityOperation target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_3403
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vquantum_info_3409
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyQuantumInfo")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vquantum_info_3409
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_3388
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_3388
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="adjoin"
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_3387
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(1).(IfStmt).getThen().(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="previous"
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(1).(IfStmt).getThen().(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_3388
		and target_0.getThen().(BlockStmt).getStmt(2) instanceof EmptyStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(LogicalAndExpr target_2, Function func, EmptyStmt target_1) {
		target_1.toString() = ";"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter vimage_3388, Parameter vexception_3388, Variable vquantum_info_3409, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="storage_class"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_3388
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="depth"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_3388
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="format"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vquantum_info_3409
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("IsHighDynamicRangeImage")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_3388
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vexception_3388
}

predicate func_3(Parameter vimage_info_3387, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="adjoin"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_3387
}

predicate func_4(Parameter vimage_info_3387, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="adjoin"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_3387
}

predicate func_5(Parameter vimage_3388, Variable vstatus_3403, Variable vquantum_info_3409, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_3403
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("SetQuantumFormat")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_3388
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vquantum_info_3409
}

predicate func_6(Parameter vimage_3388, Parameter vexception_3388, Variable v__func__, ExprStmt target_6) {
		target_6.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_6.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_3388
		and target_6.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_6.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_6.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_6.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_6.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_6.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_6.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_6.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_6.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_3388
}

predicate func_7(Variable vstatus_3403, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vstatus_3403
}

predicate func_8(Variable vquantum_info_3409, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("SetQuantumMinIsWhite")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vquantum_info_3409
}

predicate func_9(Parameter vimage_3388, Parameter vexception_3388, Variable v__func__, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_3388
		and target_9.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_9.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_9.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_9.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_9.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_9.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_9.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_9.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_9.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_3388
}

from Function func, Parameter vimage_info_3387, Parameter vimage_3388, Parameter vexception_3388, Variable vstatus_3403, Variable vquantum_info_3409, Variable v__func__, EmptyStmt target_1, LogicalAndExpr target_2, EqualityOperation target_3, EqualityOperation target_4, ExprStmt target_5, ExprStmt target_6, EqualityOperation target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(vimage_info_3387, vimage_3388, vexception_3388, vstatus_3403, vquantum_info_3409, v__func__, target_2, target_3, target_4, target_5, target_6, target_7, target_8, target_9)
and func_1(target_2, func, target_1)
and func_2(vimage_3388, vexception_3388, vquantum_info_3409, target_2)
and func_3(vimage_info_3387, target_3)
and func_4(vimage_info_3387, target_4)
and func_5(vimage_3388, vstatus_3403, vquantum_info_3409, target_5)
and func_6(vimage_3388, vexception_3388, v__func__, target_6)
and func_7(vstatus_3403, target_7)
and func_8(vquantum_info_3409, target_8)
and func_9(vimage_3388, vexception_3388, v__func__, target_9)
and vimage_info_3387.getType().hasName("const ImageInfo *")
and vimage_3388.getType().hasName("Image *")
and vexception_3388.getType().hasName("ExceptionInfo *")
and vstatus_3403.getType().hasName("MagickBooleanType")
and vquantum_info_3409.getType().hasName("QuantumInfo *")
and v__func__.getType() instanceof ArrayType
and vimage_info_3387.getParentScope+() = func
and vimage_3388.getParentScope+() = func
and vexception_3388.getParentScope+() = func
and vstatus_3403.getParentScope+() = func
and vquantum_info_3409.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
