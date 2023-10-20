/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-fsck_tree
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/fsck-tree
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-fsck.c-fsck_tree CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vname_593, LogicalOrExpr target_21, LogicalOrExpr target_19, FunctionCall target_1) {
		target_1.getTarget().hasName("is_hfs_dotgitattributes")
		and not target_1.getTarget().hasName("is_hfs_dotmailmap")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_21.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
}

predicate func_2(Variable vname_593, LogicalOrExpr target_19, LogicalOrExpr target_20, FunctionCall target_2) {
		target_2.getTarget().hasName("is_ntfs_dotgitattributes")
		and not target_2.getTarget().hasName("is_ntfs_dotmailmap")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_20.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_4(Function func, StringLiteral target_4) {
		target_4.getValue()=".gitattributes is a symlink"
		and not target_4.getValue()=".mailmap is a symlink"
		and target_4.getEnclosingFunction() = func
}

predicate func_6(Function func, StringLiteral target_6) {
		target_6.getValue()=".mailmap is a symlink"
		and not target_6.getValue()=".gitattributes is a symlink"
		and target_6.getEnclosingFunction() = func
}

predicate func_15(Variable vmode_592, ExprStmt target_22, EqualityOperation target_18, NotExpr target_23) {
	exists(NotExpr target_15 |
		target_15.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vmode_592
		and target_15.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_15.getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="40960"
		and target_15.getParent().(IfStmt).getThen()=target_22
		and target_18.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_15.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_15.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_23.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_16(Variable ventry_oid_594, Parameter voptions_563, LogicalOrExpr target_20, ExprStmt target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_22) {
	exists(ExprStmt target_16 |
		target_16.getExpr().(FunctionCall).getTarget().hasName("oidset_insert")
		and target_16.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gitattributes_found"
		and target_16.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions_563
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ventry_oid_594
		and target_16.getParent().(IfStmt).getCondition()=target_20
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_16.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_26.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_16.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_17(Variable vretval_565, Variable vname_593, Parameter voptions_563, Parameter vtree_oid_561, ExprStmt target_27, ExprStmt target_22, LogicalOrExpr target_28, LogicalOrExpr target_19) {
	exists(IfStmt target_17 |
		target_17.getCondition() instanceof EqualityOperation
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("is_hfs_dotgitignore")
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("is_ntfs_dotgitignore")
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vretval_565
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_563
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtree_oid_561
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(StringLiteral).getValue()=".gitignore is a symlink"
		and target_17.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition() instanceof LogicalOrExpr
		and target_17.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vretval_565
		and target_17.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_17.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_563
		and target_17.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtree_oid_561
		and target_17.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(StringLiteral).getValue()=".mailmap is a symlink"
		and target_27.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_22.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation())
		and target_28.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_18(Variable vmode_592, BlockStmt target_29, EqualityOperation target_18) {
		target_18.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vmode_592
		and target_18.getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_18.getAnOperand().(Literal).getValue()="40960"
		and target_18.getParent().(IfStmt).getThen()=target_29
}

predicate func_19(ExprStmt target_26, Function func, LogicalOrExpr target_19) {
		target_19.getAnOperand() instanceof FunctionCall
		and target_19.getAnOperand() instanceof FunctionCall
		and target_19.getParent().(IfStmt).getThen()=target_26
		and target_19.getEnclosingFunction() = func
}

predicate func_20(Variable vname_593, ExprStmt target_22, LogicalOrExpr target_20) {
		target_20.getAnOperand().(FunctionCall).getTarget().hasName("is_hfs_dotmailmap")
		and target_20.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_20.getAnOperand().(FunctionCall).getTarget().hasName("is_ntfs_dotmailmap")
		and target_20.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_20.getParent().(IfStmt).getThen()=target_22
}

predicate func_21(Variable vname_593, LogicalOrExpr target_21) {
		target_21.getAnOperand().(FunctionCall).getTarget().hasName("is_hfs_dotgitignore")
		and target_21.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_21.getAnOperand().(FunctionCall).getTarget().hasName("is_ntfs_dotgitignore")
		and target_21.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
}

predicate func_22(Variable vretval_565, Parameter voptions_563, Parameter vtree_oid_561, ExprStmt target_22) {
		target_22.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vretval_565
		and target_22.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_22.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_563
		and target_22.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtree_oid_561
		and target_22.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3) instanceof EnumConstantAccess
		and target_22.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4) instanceof StringLiteral
}

predicate func_23(Variable vmode_592, NotExpr target_23) {
		target_23.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vmode_592
		and target_23.getOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="61440"
		and target_23.getOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="40960"
}

predicate func_24(Variable ventry_oid_594, Parameter voptions_563, ExprStmt target_24) {
		target_24.getExpr().(FunctionCall).getTarget().hasName("oidset_insert")
		and target_24.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gitmodules_found"
		and target_24.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions_563
		and target_24.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ventry_oid_594
}

predicate func_25(Variable ventry_oid_594, Parameter voptions_563, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("oidset_insert")
		and target_25.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gitmodules_found"
		and target_25.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=voptions_563
		and target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=ventry_oid_594
}

predicate func_26(Variable vretval_565, Parameter voptions_563, Parameter vtree_oid_561, ExprStmt target_26) {
		target_26.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vretval_565
		and target_26.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_26.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_563
		and target_26.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtree_oid_561
		and target_26.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3) instanceof EnumConstantAccess
		and target_26.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4) instanceof StringLiteral
}

predicate func_27(Variable vretval_565, Parameter voptions_563, Parameter vtree_oid_561, ExprStmt target_27) {
		target_27.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vretval_565
		and target_27.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_27.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_563
		and target_27.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtree_oid_561
		and target_27.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(StringLiteral).getValue()=".gitmodules is a symbolic link"
}

predicate func_28(Variable vname_593, LogicalOrExpr target_28) {
		target_28.getAnOperand().(FunctionCall).getTarget().hasName("is_hfs_dotgitmodules")
		and target_28.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_28.getAnOperand().(FunctionCall).getTarget().hasName("is_ntfs_dotgitmodules")
		and target_28.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
}

predicate func_29(Variable vretval_565, Variable vname_593, Parameter voptions_563, Parameter vtree_oid_561, BlockStmt target_29) {
		target_29.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("is_hfs_dotgitignore")
		and target_29.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_29.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("is_ntfs_dotgitignore")
		and target_29.getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_593
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vretval_565
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=voptions_563
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtree_oid_561
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3) instanceof EnumConstantAccess
		and target_29.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(StringLiteral).getValue()=".gitignore is a symlink"
}

from Function func, Variable vretval_565, Variable vmode_592, Variable vname_593, Variable ventry_oid_594, Parameter voptions_563, Parameter vtree_oid_561, FunctionCall target_1, FunctionCall target_2, StringLiteral target_4, StringLiteral target_6, EqualityOperation target_18, LogicalOrExpr target_19, LogicalOrExpr target_20, LogicalOrExpr target_21, ExprStmt target_22, NotExpr target_23, ExprStmt target_24, ExprStmt target_25, ExprStmt target_26, ExprStmt target_27, LogicalOrExpr target_28, BlockStmt target_29
where
func_1(vname_593, target_21, target_19, target_1)
and func_2(vname_593, target_19, target_20, target_2)
and func_4(func, target_4)
and func_6(func, target_6)
and not func_15(vmode_592, target_22, target_18, target_23)
and not func_16(ventry_oid_594, voptions_563, target_20, target_24, target_25, target_26, target_22)
and not func_17(vretval_565, vname_593, voptions_563, vtree_oid_561, target_27, target_22, target_28, target_19)
and func_18(vmode_592, target_29, target_18)
and func_19(target_26, func, target_19)
and func_20(vname_593, target_22, target_20)
and func_21(vname_593, target_21)
and func_22(vretval_565, voptions_563, vtree_oid_561, target_22)
and func_23(vmode_592, target_23)
and func_24(ventry_oid_594, voptions_563, target_24)
and func_25(ventry_oid_594, voptions_563, target_25)
and func_26(vretval_565, voptions_563, vtree_oid_561, target_26)
and func_27(vretval_565, voptions_563, vtree_oid_561, target_27)
and func_28(vname_593, target_28)
and func_29(vretval_565, vname_593, voptions_563, vtree_oid_561, target_29)
and vretval_565.getType().hasName("int")
and vmode_592.getType().hasName("unsigned short")
and vname_593.getType().hasName("const char *")
and ventry_oid_594.getType().hasName("const object_id *")
and voptions_563.getType().hasName("fsck_options *")
and vtree_oid_561.getType().hasName("const object_id *")
and vretval_565.getParentScope+() = func
and vmode_592.getParentScope+() = func
and vname_593.getParentScope+() = func
and ventry_oid_594.getParentScope+() = func
and voptions_563.getParentScope+() = func
and vtree_oid_561.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
