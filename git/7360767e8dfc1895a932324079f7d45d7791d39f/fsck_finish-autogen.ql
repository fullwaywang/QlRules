/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-fsck_finish
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/fsck-finish
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-fsck.c-fsck_finish CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter voptions_1232, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="gitmodules_found"
		and target_0.getQualifier().(VariableAccess).getTarget()=voptions_1232
}

predicate func_1(Parameter voptions_1232, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="gitmodules_done"
		and target_1.getQualifier().(VariableAccess).getTarget()=voptions_1232
}

predicate func_2(Variable void_1236, Parameter voptions_1232, FunctionCall target_2) {
		target_2.getTarget().hasName("oidset_contains")
		and not target_2.getTarget().hasName("fsck_blobs")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gitmodules_done"
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions_1232
		and target_2.getArgument(1).(VariableAccess).getTarget()=void_1236
}

predicate func_3(Variable void_1236, FunctionCall target_3) {
		target_3.getTarget().hasName("is_promisor_object")
		and not target_3.getTarget().hasName("fsck_blobs")
		and target_3.getArgument(0).(VariableAccess).getTarget()=void_1236
}

predicate func_8(Parameter voptions_1232, AddressOfExpr target_8) {
		target_8.getOperand().(PointerFieldAccess).getTarget().getName()="gitmodules_found"
		and target_8.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions_1232
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_10(Parameter voptions_1232, VariableAccess target_10) {
		target_10.getTarget()=voptions_1232
		and target_10.getParent().(FunctionCall).getParent().(AssignOrExpr).getRValue() instanceof FunctionCall
}

predicate func_12(Parameter voptions_1232, VariableAccess target_12) {
		target_12.getTarget()=voptions_1232
		and target_12.getParent().(FunctionCall).getParent().(AssignOrExpr).getRValue() instanceof FunctionCall
}

predicate func_13(Function func, DeclStmt target_13) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Function func, DeclStmt target_14) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Variable viter_1235, FunctionCall target_15) {
		target_15.getTarget().hasName("oidset_iter_init")
		and target_15.getArgument(0) instanceof AddressOfExpr
		and target_15.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=viter_1235
}

predicate func_16(Variable vret_1234, Variable viter_1235, Variable void_1236, Variable vtype_1240, Variable vbuf_1242, Variable vthe_repository, Function func, WhileStmt target_16) {
		target_16.getCondition().(AssignExpr).getLValue().(VariableAccess).getTarget()=void_1236
		and target_16.getCondition().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("oidset_iter_next")
		and target_16.getCondition().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=viter_1235
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(3).(IfStmt).getCondition() instanceof FunctionCall
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(3).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_1242
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("repo_read_object_file")
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vthe_repository
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=void_1236
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_1242
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof FunctionCall
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(5).(IfStmt).getThen().(BlockStmt).getStmt(2).(ContinueStmt).toString() = "continue;"
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1240
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vret_1234
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("fsck_blob")
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getElse().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vret_1234
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(6).(IfStmt).getElse().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("free")
		and target_16.getStmt().(BlockStmt).getStmt(0).(BlockStmt).getStmt(7).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1242
		and target_16.getStmt().(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_16
}

/*predicate func_20(Function func, IfStmt target_20) {
		target_20.getCondition() instanceof FunctionCall
		and target_20.getThen().(ContinueStmt).toString() = "continue;"
		and target_20.getEnclosingFunction() = func
}

*/
/*predicate func_21(Variable void_1236, Variable vtype_1240, Variable vsize_1241, Variable vbuf_1242, Variable vthe_repository, ExprStmt target_21) {
		target_21.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbuf_1242
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("repo_read_object_file")
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vthe_repository
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=void_1236
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtype_1240
		and target_21.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsize_1241
}

*/
/*predicate func_22(Variable vret_1234, Variable void_1236, Variable vbuf_1242, Parameter voptions_1232, IfStmt target_22) {
		target_22.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vbuf_1242
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition() instanceof FunctionCall
		and target_22.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ContinueStmt).toString() = "continue;"
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vret_1234
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_1232
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=void_1236
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(3) instanceof EnumConstantAccess
		and target_22.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(4).(StringLiteral).getValue()="unable to read .gitmodules blob"
		and target_22.getThen().(BlockStmt).getStmt(2).(ContinueStmt).toString() = "continue;"
}

*/
/*predicate func_23(NotExpr target_34, Function func, IfStmt target_23) {
		target_23.getCondition() instanceof FunctionCall
		and target_23.getThen().(ContinueStmt).toString() = "continue;"
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
		and target_23.getEnclosingFunction() = func
}

*/
/*predicate func_24(Variable vret_1234, Variable void_1236, Parameter voptions_1232, NotExpr target_34, ExprStmt target_24) {
		target_24.getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vret_1234
		and target_24.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_24.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_1232
		and target_24.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=void_1236
		and target_24.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(2) instanceof EnumConstantAccess
		and target_24.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(3) instanceof EnumConstantAccess
		and target_24.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(4).(StringLiteral).getValue()="unable to read .gitmodules blob"
		and target_24.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
}

*/
/*predicate func_25(Variable void_1236, Parameter voptions_1232, FunctionCall target_25) {
		target_25.getTarget().hasName("report")
		and target_25.getArgument(0).(VariableAccess).getTarget()=voptions_1232
		and target_25.getArgument(1).(VariableAccess).getTarget()=void_1236
		and target_25.getArgument(2) instanceof EnumConstantAccess
		and target_25.getArgument(3) instanceof EnumConstantAccess
		and target_25.getArgument(4).(StringLiteral).getValue()="unable to read .gitmodules blob"
}

*/
/*predicate func_26(NotExpr target_34, Function func, ContinueStmt target_26) {
		target_26.toString() = "continue;"
		and target_26.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_34
		and target_26.getEnclosingFunction() = func
}

*/
/*predicate func_27(Variable vret_1234, Variable void_1236, Variable vtype_1240, Variable vsize_1241, Variable vbuf_1242, Parameter voptions_1232, IfStmt target_27) {
		target_27.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtype_1240
		and target_27.getCondition().(EqualityOperation).getAnOperand() instanceof EnumConstantAccess
		and target_27.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vret_1234
		and target_27.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("fsck_blob")
		and target_27.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=void_1236
		and target_27.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuf_1242
		and target_27.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_1241
		and target_27.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voptions_1232
		and target_27.getElse().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vret_1234
		and target_27.getElse().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_27.getElse().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_1232
		and target_27.getElse().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=void_1236
		and target_27.getElse().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtype_1240
		and target_27.getElse().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(3) instanceof EnumConstantAccess
		and target_27.getElse().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(4).(StringLiteral).getValue()="non-blob found at .gitmodules"
}

*/
/*predicate func_28(Variable void_1236, Variable vsize_1241, Variable vbuf_1242, Parameter voptions_1232, FunctionCall target_28) {
		target_28.getTarget().hasName("fsck_blob")
		and target_28.getArgument(0).(VariableAccess).getTarget()=void_1236
		and target_28.getArgument(1).(VariableAccess).getTarget()=vbuf_1242
		and target_28.getArgument(2).(VariableAccess).getTarget()=vsize_1241
		and target_28.getArgument(3).(VariableAccess).getTarget()=voptions_1232
}

*/
/*predicate func_29(Variable vret_1234, Variable void_1236, Variable vtype_1240, Parameter voptions_1232, AssignOrExpr target_29) {
		target_29.getLValue().(VariableAccess).getTarget()=vret_1234
		and target_29.getRValue().(FunctionCall).getTarget().hasName("report")
		and target_29.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_1232
		and target_29.getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=void_1236
		and target_29.getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vtype_1240
		and target_29.getRValue().(FunctionCall).getArgument(3) instanceof EnumConstantAccess
		and target_29.getRValue().(FunctionCall).getArgument(4).(StringLiteral).getValue()="non-blob found at .gitmodules"
}

*/
/*predicate func_30(Variable vbuf_1242, ExprStmt target_30) {
		target_30.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_30.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_1242
}

*/
/*predicate func_31(Function func, LabelStmt target_31) {
		target_31.toString() = "label ...:"
		and target_31.getEnclosingFunction() = func
}

*/
predicate func_32(Parameter voptions_1232, Function func, ExprStmt target_32) {
		target_32.getExpr().(FunctionCall).getTarget().hasName("oidset_clear")
		and target_32.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gitmodules_found"
		and target_32.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions_1232
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_32
}

predicate func_33(Parameter voptions_1232, Function func, ExprStmt target_33) {
		target_33.getExpr().(FunctionCall).getTarget().hasName("oidset_clear")
		and target_33.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gitmodules_done"
		and target_33.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions_1232
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_33
}

predicate func_34(Variable vbuf_1242, NotExpr target_34) {
		target_34.getOperand().(VariableAccess).getTarget()=vbuf_1242
}

from Function func, Variable vret_1234, Variable viter_1235, Variable void_1236, Variable vtype_1240, Variable vsize_1241, Variable vbuf_1242, Variable vthe_repository, Parameter voptions_1232, PointerFieldAccess target_0, PointerFieldAccess target_1, FunctionCall target_2, FunctionCall target_3, AddressOfExpr target_8, VariableAccess target_10, VariableAccess target_12, DeclStmt target_13, DeclStmt target_14, FunctionCall target_15, WhileStmt target_16, ExprStmt target_32, ExprStmt target_33, NotExpr target_34
where
func_0(voptions_1232, target_0)
and func_1(voptions_1232, target_1)
and func_2(void_1236, voptions_1232, target_2)
and func_3(void_1236, target_3)
and func_8(voptions_1232, target_8)
and func_10(voptions_1232, target_10)
and func_12(voptions_1232, target_12)
and func_13(func, target_13)
and func_14(func, target_14)
and func_15(viter_1235, target_15)
and func_16(vret_1234, viter_1235, void_1236, vtype_1240, vbuf_1242, vthe_repository, func, target_16)
and func_32(voptions_1232, func, target_32)
and func_33(voptions_1232, func, target_33)
and func_34(vbuf_1242, target_34)
and vret_1234.getType().hasName("int")
and viter_1235.getType().hasName("oidset_iter")
and void_1236.getType().hasName("const object_id *")
and vtype_1240.getType().hasName("object_type")
and vsize_1241.getType().hasName("unsigned long")
and vbuf_1242.getType().hasName("char *")
and vthe_repository.getType().hasName("repository *")
and voptions_1232.getType().hasName("fsck_options *")
and vret_1234.getParentScope+() = func
and viter_1235.getParentScope+() = func
and void_1236.getParentScope+() = func
and vtype_1240.getParentScope+() = func
and vsize_1241.getParentScope+() = func
and vbuf_1242.getParentScope+() = func
and not vthe_repository.getParentScope+() = func
and voptions_1232.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
