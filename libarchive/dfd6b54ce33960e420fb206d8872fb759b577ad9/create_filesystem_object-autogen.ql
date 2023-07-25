/**
 * @name libarchive-dfd6b54ce33960e420fb206d8872fb759b577ad9-create_filesystem_object
 * @id cpp/libarchive/dfd6b54ce33960e420fb206d8872fb759b577ad9/create-filesystem-object
 * @description libarchive-dfd6b54ce33960e420fb206d8872fb759b577ad9-libarchive/archive_write_disk_posix.c-create_filesystem_object CVE-2016-5418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_8, Function func) {
	exists(DoStmt target_0 |
		target_0.getCondition().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="s"
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_0.getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="length"
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_0.getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buffer_length"
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_0.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vlinkname_2014, EqualityOperation target_8, ExprStmt target_9) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("char *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("strdup")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlinkname_2014
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_8, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("char *")
		and target_2.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getThen().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter va_2011, Variable vr_2016, EqualityOperation target_8, ExprStmt target_10) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_2016
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cleanup_pathname_fsobj")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="flags"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2011
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter va_2011, Variable vr_2016, EqualityOperation target_8) {
	exists(IfStmt target_4 |
		target_4.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vr_2016
		and target_4.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2011
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="s"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("archive_string")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_4.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8)
}

predicate func_5(Parameter va_2011, Variable vr_2016, EqualityOperation target_8) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_2016
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_symlinks_fsobj")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("archive_string")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="flags"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2011
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8)
}

predicate func_6(Parameter va_2011, Variable vr_2016, EqualityOperation target_8, ExprStmt target_9) {
	exists(IfStmt target_6 |
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vr_2016
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("archive_set_error")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="archive"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2011
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("int")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="s"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("archive_string")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_6.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(EqualityOperation target_8, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("char *")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(7)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Variable vlinkname_2014, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vlinkname_2014
		and target_8.getAnOperand().(Literal).getValue()="0"
}

predicate func_9(Parameter va_2011, Variable vlinkname_2014, Variable vr_2016, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_2016
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getTarget().hasName("link")
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlinkname_2014
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2011
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_9.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_10(Parameter va_2011, Variable vlinkname_2014, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlinkname_2014
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("archive_entry_hardlink")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="entry"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=va_2011
}

from Function func, Parameter va_2011, Variable vlinkname_2014, Variable vr_2016, EqualityOperation target_8, ExprStmt target_9, ExprStmt target_10
where
not func_0(target_8, func)
and not func_1(vlinkname_2014, target_8, target_9)
and not func_2(target_8, func)
and not func_3(va_2011, vr_2016, target_8, target_10)
and not func_4(va_2011, vr_2016, target_8)
and not func_5(va_2011, vr_2016, target_8)
and not func_6(va_2011, vr_2016, target_8, target_9)
and not func_7(target_8, func)
and func_8(vlinkname_2014, target_8)
and func_9(va_2011, vlinkname_2014, vr_2016, target_9)
and func_10(va_2011, vlinkname_2014, target_10)
and va_2011.getType().hasName("archive_write_disk *")
and vlinkname_2014.getType().hasName("const char *")
and vr_2016.getType().hasName("int")
and va_2011.getParentScope+() = func
and vlinkname_2014.getParentScope+() = func
and vr_2016.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
