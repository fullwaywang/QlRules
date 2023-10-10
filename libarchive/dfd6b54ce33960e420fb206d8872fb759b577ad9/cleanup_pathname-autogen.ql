/**
 * @name libarchive-dfd6b54ce33960e420fb206d8872fb759b577ad9-cleanup_pathname
 * @id cpp/libarchive/dfd6b54ce33960e420fb206d8872fb759b577ad9/cleanup-pathname
 * @description libarchive-dfd6b54ce33960e420fb206d8872fb759b577ad9-libarchive/archive_write_disk_posix.c-cleanup_pathname CVE-2016-5418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="1"
		and not target_0.getValue()="0"
		and target_0.getParent().(UnaryMinusExpr).getParent().(FunctionCall).getArgument(1) instanceof UnaryMinusExpr
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="Invalid empty pathname"
		and not target_1.getValue()="%s"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Parameter va_2547, FunctionCall target_2) {
		target_2.getTarget().hasName("archive_set_error")
		and not target_2.getTarget().hasName("archive_string_free")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_2.getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_2.getArgument(2).(StringLiteral).getValue()="Path is absolute"
}

predicate func_5(Function func) {
	exists(DoStmt target_5 |
		target_5.getCondition() instanceof Literal
		and target_5.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="s"
		and target_5.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_5.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_5.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer_length"
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_5.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_5))
}

/*predicate func_6(Function func) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="s"
		and target_6.getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_6.getEnclosingFunction() = func)
}

*/
/*predicate func_7(Function func) {
	exists(AssignExpr target_7 |
		target_7.getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_7.getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_7.getRValue() instanceof Literal
		and target_7.getEnclosingFunction() = func)
}

*/
/*predicate func_8(Function func) {
	exists(AssignExpr target_8 |
		target_8.getLValue().(PointerFieldAccess).getTarget().getName()="buffer_length"
		and target_8.getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_8.getRValue() instanceof Literal
		and target_8.getEnclosingFunction() = func)
}

*/
predicate func_9(Parameter va_2547, AddressOfExpr target_61) {
	exists(AssignExpr target_9 |
		target_9.getLValue().(VariableAccess).getType().hasName("int")
		and target_9.getRValue().(FunctionCall).getTarget().hasName("cleanup_pathname_fsobj")
		and target_9.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="name"
		and target_9.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_9.getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_9.getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_9.getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="flags"
		and target_9.getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_9.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_61.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_12(Function func) {
	exists(ValueFieldAccess target_12 |
		target_12.getTarget().getName()="s"
		and target_12.getQualifier().(VariableAccess).getType().hasName("archive_string")
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(Function func) {
	exists(AddressOfExpr target_13 |
		target_13.getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_13.getEnclosingFunction() = func)
}

predicate func_15(Parameter va_2547, Variable vsrc_2549, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="name"
		and target_15.getQualifier().(VariableAccess).getTarget()=va_2547
		and target_15.getParent().(AssignExpr).getRValue() = target_15
		and target_15.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsrc_2549
}

predicate func_16(Parameter va_2547, BlockStmt target_62, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="flags"
		and target_16.getQualifier().(VariableAccess).getTarget()=va_2547
		and target_16.getParent().(BitwiseAndExpr).getRightOperand() instanceof Literal
		and target_16.getParent().(BitwiseAndExpr).getParent().(IfStmt).getThen()=target_62
}

/*predicate func_24(Parameter va_2547, Variable vdest_2549, Variable vsrc_2549, AddressOfExpr target_63, EqualityOperation target_26, VariableAccess target_24) {
		target_24.getTarget()=vdest_2549
		and target_24.getParent().(AssignExpr).getLValue() = target_24
		and target_24.getParent().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsrc_2549
		and target_24.getParent().(AssignExpr).getRValue().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_24.getParent().(AssignExpr).getRValue().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_24.getParent().(AssignExpr).getRValue().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_63.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_24.getParent().(AssignExpr).getRValue().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_26.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

*/
/*predicate func_25(Parameter va_2547, Variable vdest_2549, Variable vsrc_2549, AssignExpr target_25) {
		target_25.getLValue().(VariableAccess).getTarget()=vsrc_2549
		and target_25.getRValue().(PointerFieldAccess).getTarget().getName()="name"
		and target_25.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_25.getParent().(AssignExpr).getRValue() = target_25
		and target_25.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdest_2549
}

*/
predicate func_26(Variable vsrc_2549, BlockStmt target_65, EqualityOperation target_26) {
		target_26.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_26.getAnOperand().(CharLiteral).getValue()="0"
		and target_26.getParent().(IfStmt).getThen()=target_65
}

predicate func_27(Parameter va_2547, BitwiseAndExpr target_69, UnaryMinusExpr target_27) {
		target_27.getValue()="-1"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_27.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_69.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_28(Function func, UnaryMinusExpr target_28) {
		target_28.getValue()="-25"
		and target_28.getEnclosingFunction() = func
}

predicate func_29(Parameter va_2547, Variable vsrc_2549, Variable vseparator_2550, Function func, IfStmt target_29) {
		target_29.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_29.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_29.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_29.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_29.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="65536"
		and target_29.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_29.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-25"
		and target_29.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vseparator_2550
		and target_29.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_29
}

/*predicate func_30(Parameter va_2547, EqualityOperation target_70, IfStmt target_30) {
		target_30.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_30.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_30.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="65536"
		and target_30.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_30.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-25"
		and target_30.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_70
}

*/
predicate func_31(Parameter va_2547, BitwiseAndExpr target_69, BitwiseAndExpr target_71, PointerFieldAccess target_31) {
		target_31.getTarget().getName()="archive"
		and target_31.getQualifier().(VariableAccess).getTarget()=va_2547
		and target_69.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_31.getQualifier().(VariableAccess).getLocation())
		and target_31.getQualifier().(VariableAccess).getLocation().isBefore(target_71.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

/*predicate func_33(BitwiseAndExpr target_69, Function func, ReturnStmt target_33) {
		target_33.getExpr().(UnaryMinusExpr).getValue()="-25"
		and target_33.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_69
		and target_33.getEnclosingFunction() = func
}

*/
/*predicate func_34(Variable vsrc_2549, Variable vseparator_2550, EqualityOperation target_70, IfStmt target_48, AssignExpr target_34) {
		target_34.getLValue().(VariableAccess).getTarget()=vseparator_2550
		and target_34.getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_34.getLValue().(VariableAccess).getLocation().isBefore(target_48.getCondition().(VariableAccess).getLocation())
}

*/
predicate func_35(Variable vsrc_2549, Variable vseparator_2550, ForStmt target_35) {
		target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(BreakStmt).toString() = "break;"
		and target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_35.getStmt().(BlockStmt).getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="46"
		and target_35.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vseparator_2550
		and target_35.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="47"
		and target_35.getStmt().(BlockStmt).getStmt(2).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_35.getStmt().(BlockStmt).getStmt(2).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_35.getStmt().(BlockStmt).getStmt(2).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_35.getStmt().(BlockStmt).getStmt(2).(WhileStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_35.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_35.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_35.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(BreakStmt).toString() = "break;"
		and target_35.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vseparator_2550
		and target_35.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_35.getStmt().(BlockStmt).getStmt(5).(LabelStmt).toString() = "label ...:"
}

/*predicate func_36(Variable vsrc_2549, IfStmt target_36) {
		target_36.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_36.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_36.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_36.getThen().(BlockStmt).getStmt(0).(BreakStmt).toString() = "break;"
		and target_36.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_36.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_36.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_36.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_36.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_36.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_36.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset() instanceof Literal
		and target_36.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="46"
		and target_36.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_36.getElse().(IfStmt).getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(BreakStmt).toString() = "break;"
}

*/
/*predicate func_37(EqualityOperation target_73, Function func, BreakStmt target_37) {
		target_37.toString() = "break;"
		and target_37.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_73
		and target_37.getEnclosingFunction() = func
}

*/
/*predicate func_38(Variable vsrc_2549, EqualityOperation target_74, ExprStmt target_38) {
		target_38.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_38.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_74
}

*/
/*predicate func_39(EqualityOperation target_74, Function func, ContinueStmt target_39) {
		target_39.toString() = "continue;"
		and target_39.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_74
		and target_39.getEnclosingFunction() = func
}

*/
/*predicate func_40(Variable vsrc_2549, EqualityOperation target_75, IfStmt target_40) {
		target_40.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_40.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_40.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_40.getThen().(BlockStmt).getStmt(0).(BreakStmt).toString() = "break;"
		and target_40.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_40.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_40.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_40.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vsrc_2549
		and target_40.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_40.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(ContinueStmt).toString() = "continue;"
		and target_40.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_40.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_40.getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="46"
		and target_40.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_75
}

*/
/*predicate func_41(EqualityOperation target_76, Function func, BreakStmt target_41) {
		target_41.toString() = "break;"
		and target_41.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_76
		and target_41.getEnclosingFunction() = func
}

*/
/*predicate func_42(Variable vsrc_2549, EqualityOperation target_77, ExprStmt target_42) {
		target_42.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vsrc_2549
		and target_42.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_42.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_77
}

*/
/*predicate func_43(EqualityOperation target_77, Function func, ContinueStmt target_43) {
		target_43.toString() = "continue;"
		and target_43.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_77
		and target_43.getEnclosingFunction() = func
}

*/
/*predicate func_44(Parameter va_2547, Variable vsrc_2549, EqualityOperation target_78, IfStmt target_44) {
		target_44.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_44.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_44.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_44.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vsrc_2549
		and target_44.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_44.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Path contains '..'"
		and target_44.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-25"
		and target_44.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_78
}

*/
/*predicate func_45(Parameter va_2547, LogicalOrExpr target_79, IfStmt target_45) {
		target_45.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_45.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_45.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="512"
		and target_45.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_45.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_45.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_45.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_45.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Path contains '..'"
		and target_45.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-25"
		and target_45.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_79
}

*/
/*predicate func_46(Parameter va_2547, FunctionCall target_46) {
		target_46.getTarget().hasName("archive_set_error")
		and target_46.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_46.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_46.getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_46.getArgument(2).(StringLiteral).getValue()="Path contains '..'"
}

*/
/*predicate func_47(BitwiseAndExpr target_71, Function func, ReturnStmt target_47) {
		target_47.getExpr().(UnaryMinusExpr).getValue()="-25"
		and target_47.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_71
		and target_47.getEnclosingFunction() = func
}

*/
predicate func_48(Variable vdest_2549, Variable vseparator_2550, IfStmt target_48) {
		target_48.getCondition().(VariableAccess).getTarget()=vseparator_2550
		and target_48.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdest_2549
		and target_48.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="47"
}

/*predicate func_49(Variable vdest_2549, Variable vsrc_2549, WhileStmt target_49) {
		target_49.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_49.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_49.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_49.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="47"
		and target_49.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdest_2549
		and target_49.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
}

*/
/*predicate func_50(Variable vsrc_2549, PointerDereferenceExpr target_50) {
		target_50.getOperand().(VariableAccess).getTarget()=vsrc_2549
}

*/
/*predicate func_52(Variable vdest_2549, Variable vsrc_2549, ExprStmt target_52) {
		target_52.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdest_2549
		and target_52.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
}

*/
/*predicate func_53(Variable vsrc_2549, IfStmt target_53) {
		target_53.getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
		and target_53.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_53.getThen().(BreakStmt).toString() = "break;"
}

*/
/*predicate func_54(Variable vsrc_2549, Variable vseparator_2550, AssignExpr target_54) {
		target_54.getLValue().(VariableAccess).getTarget()=vseparator_2550
		and target_54.getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vsrc_2549
}

*/
/*predicate func_55(Function func, LabelStmt target_55) {
		target_55.toString() = "label ...:"
		and target_55.getEnclosingFunction() = func
}

*/
predicate func_56(Function func, LabelStmt target_56) {
		target_56.toString() = "label ...:"
		and target_56.getEnclosingFunction() = func
}

predicate func_57(Parameter va_2547, Variable vdest_2549, Variable vseparator_2550, IfStmt target_57) {
		target_57.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdest_2549
		and target_57.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="name"
		and target_57.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_57.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vseparator_2550
		and target_57.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="47"
		and target_57.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="46"
}

/*predicate func_58(Variable vdest_2549, Variable vseparator_2550, IfStmt target_58) {
		target_58.getCondition().(VariableAccess).getTarget()=vseparator_2550
		and target_58.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdest_2549
		and target_58.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="47"
		and target_58.getElse().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vdest_2549
		and target_58.getElse().(ExprStmt).getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="46"
}

*/
predicate func_59(Variable vdest_2549, ExprStmt target_59) {
		target_59.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdest_2549
		and target_59.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_60(Function func, ReturnStmt target_60) {
		target_60.getExpr() instanceof Literal
		and target_60.getEnclosingFunction() = func
}

predicate func_61(Parameter va_2547, AddressOfExpr target_61) {
		target_61.getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_61.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
}

predicate func_62(BlockStmt target_62) {
		target_62.getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_62.getStmt(1) instanceof ReturnStmt
}

predicate func_63(Parameter va_2547, AddressOfExpr target_63) {
		target_63.getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_63.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
}

predicate func_65(Parameter va_2547, BlockStmt target_65) {
		target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof UnaryMinusExpr
		and target_65.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
}

predicate func_69(Parameter va_2547, BitwiseAndExpr target_69) {
		target_69.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_69.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_69.getRightOperand() instanceof Literal
}

predicate func_70(EqualityOperation target_70) {
		target_70.getAnOperand() instanceof PointerDereferenceExpr
		and target_70.getAnOperand() instanceof CharLiteral
}

predicate func_71(Parameter va_2547, BitwiseAndExpr target_71) {
		target_71.getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_71.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2547
		and target_71.getRightOperand() instanceof Literal
}

predicate func_73(EqualityOperation target_73) {
		target_73.getAnOperand() instanceof ArrayExpr
		and target_73.getAnOperand() instanceof CharLiteral
}

predicate func_74(EqualityOperation target_74) {
		target_74.getAnOperand() instanceof ArrayExpr
		and target_74.getAnOperand() instanceof CharLiteral
}

predicate func_75(EqualityOperation target_75) {
		target_75.getAnOperand() instanceof ArrayExpr
		and target_75.getAnOperand() instanceof CharLiteral
}

predicate func_76(EqualityOperation target_76) {
		target_76.getAnOperand() instanceof ArrayExpr
		and target_76.getAnOperand() instanceof CharLiteral
}

predicate func_77(EqualityOperation target_77) {
		target_77.getAnOperand() instanceof ArrayExpr
		and target_77.getAnOperand() instanceof CharLiteral
}

predicate func_78(EqualityOperation target_78) {
		target_78.getAnOperand() instanceof ArrayExpr
		and target_78.getAnOperand() instanceof CharLiteral
}

predicate func_79(LogicalOrExpr target_79) {
		target_79.getAnOperand() instanceof EqualityOperation
		and target_79.getAnOperand() instanceof EqualityOperation
}

from Function func, Parameter va_2547, Variable vdest_2549, Variable vsrc_2549, Variable vseparator_2550, Literal target_0, StringLiteral target_1, FunctionCall target_2, PointerFieldAccess target_15, PointerFieldAccess target_16, EqualityOperation target_26, UnaryMinusExpr target_27, UnaryMinusExpr target_28, IfStmt target_29, PointerFieldAccess target_31, ForStmt target_35, IfStmt target_48, LabelStmt target_56, IfStmt target_57, ExprStmt target_59, ReturnStmt target_60, AddressOfExpr target_61, BlockStmt target_62, AddressOfExpr target_63, BlockStmt target_65, BitwiseAndExpr target_69, EqualityOperation target_70, BitwiseAndExpr target_71, EqualityOperation target_73, EqualityOperation target_74, EqualityOperation target_75, EqualityOperation target_76, EqualityOperation target_77, EqualityOperation target_78, LogicalOrExpr target_79
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(va_2547, target_2)
and not func_5(func)
and not func_9(va_2547, target_61)
and not func_12(func)
and not func_13(func)
and func_15(va_2547, vsrc_2549, target_15)
and func_16(va_2547, target_62, target_16)
and func_26(vsrc_2549, target_65, target_26)
and func_27(va_2547, target_69, target_27)
and func_28(func, target_28)
and func_29(va_2547, vsrc_2549, vseparator_2550, func, target_29)
and func_31(va_2547, target_69, target_71, target_31)
and func_35(vsrc_2549, vseparator_2550, target_35)
and func_48(vdest_2549, vseparator_2550, target_48)
and func_56(func, target_56)
and func_57(va_2547, vdest_2549, vseparator_2550, target_57)
and func_59(vdest_2549, target_59)
and func_60(func, target_60)
and func_61(va_2547, target_61)
and func_62(target_62)
and func_63(va_2547, target_63)
and func_65(va_2547, target_65)
and func_69(va_2547, target_69)
and func_70(target_70)
and func_71(va_2547, target_71)
and func_73(target_73)
and func_74(target_74)
and func_75(target_75)
and func_76(target_76)
and func_77(target_77)
and func_78(target_78)
and func_79(target_79)
and va_2547.getType().hasName("archive_write_disk *")
and vdest_2549.getType().hasName("char *")
and vsrc_2549.getType().hasName("char *")
and vseparator_2550.getType().hasName("char")
and va_2547.getParentScope+() = func
and vdest_2549.getParentScope+() = func
and vsrc_2549.getParentScope+() = func
and vseparator_2550.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
