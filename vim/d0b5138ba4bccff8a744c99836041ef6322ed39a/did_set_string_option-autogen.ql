/**
 * @name vim-d0b5138ba4bccff8a744c99836041ef6322ed39a-did_set_string_option
 * @id cpp/vim/d0b5138ba4bccff8a744c99836041ef6322ed39a/did-set-string-option
 * @description vim-d0b5138ba4bccff8a744c99836041ef6322ed39a-src/option.c-did_set_string_option CVE-2016-1248
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verrmsg_5838, Variable ve_invarg, Parameter vvarp_5832, EqualityOperation target_4, ExprStmt target_5, PointerDereferenceExpr target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("valid_filetype")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvarp_5832
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_5838
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_invarg
		and target_0.getElse() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_6.getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable verrmsg_5838, Variable vgvarp_5841, Variable ve_invarg, Parameter vvarp_5832, EqualityOperation target_7, ExprStmt target_8, EqualityOperation target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgvarp_5841
		and target_1.getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("char_u *")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("valid_filetype")
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vvarp_5832
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_5838
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_invarg
		and target_1.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vgvarp_5841
		and target_1.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("char_u *")
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("valid_filetype")
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_5838
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_invarg
		and target_1.getElse().(IfStmt).getElse() instanceof BlockStmt
		and target_1.getParent().(IfStmt).getParent().(IfStmt).getElse().(IfStmt).getElse()=target_1
		and target_1.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_9.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable verrmsg_5838, EqualityOperation target_4, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_5838
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("keymap_init")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
}

predicate func_3(Variable vs_5839, Variable vp_5839, Parameter vvarp_5832, Variable vp_ww, Variable vp_shm, Variable vp_cpo, EqualityOperation target_7, BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_5839
		and target_3.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_3.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvarp_5832
		and target_3.getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_ww
		and target_3.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_5839
		and target_3.getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="bshl<>[],~"
		and target_3.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvarp_5832
		and target_3.getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_shm
		and target_3.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_5839
		and target_3.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="rmfixlnwaWtToOsAIcqF"
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvarp_5832
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vp_cpo
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_5839
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="aAbBcCdDeEfFgHiIjJkKlLmMnoOpPqrRsStuvwWxXyZ$!%*-+<>#{|&/\\.;"
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvarp_5832
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="b_p_fo"
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vp_5839
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="tcroq2vlb1mMBn,awj"
		and target_3.getStmt(2).(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vvarp_5832
		and target_3.getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vp_5839
		and target_3.getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ForStmt).getCondition().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vs_5839
		and target_3.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(0).(ForStmt).getUpdate().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget()=vs_5839
		and target_3.getStmt(3).(IfStmt).getThen().(BlockStmt).getStmt(0).(BlockStmt).getStmt(1).(LabelStmt).toString() = "label ...:"
		and target_3.getParent().(IfStmt).getParent().(IfStmt).getCondition()=target_7
}

predicate func_4(Parameter vvarp_5832, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vvarp_5832
		and target_4.getAnOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="b_p_keymap"
}

predicate func_5(Variable verrmsg_5838, Variable ve_invarg, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_5838
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_invarg
}

predicate func_6(Parameter vvarp_5832, PointerDereferenceExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vvarp_5832
}

predicate func_7(Parameter vvarp_5832, EqualityOperation target_7) {
		target_7.getAnOperand().(VariableAccess).getTarget()=vvarp_5832
}

predicate func_8(Variable verrmsg_5838, Variable ve_invarg, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verrmsg_5838
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=ve_invarg
}

predicate func_9(Variable vgvarp_5841, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vgvarp_5841
}

from Function func, Variable verrmsg_5838, Variable vs_5839, Variable vp_5839, Variable vgvarp_5841, Variable ve_invarg, Parameter vvarp_5832, Variable vp_ww, Variable vp_shm, Variable vp_cpo, ExprStmt target_2, BlockStmt target_3, EqualityOperation target_4, ExprStmt target_5, PointerDereferenceExpr target_6, EqualityOperation target_7, ExprStmt target_8, EqualityOperation target_9
where
not func_0(verrmsg_5838, ve_invarg, vvarp_5832, target_4, target_5, target_6)
and not func_1(verrmsg_5838, vgvarp_5841, ve_invarg, vvarp_5832, target_7, target_8, target_9)
and func_2(verrmsg_5838, target_4, target_2)
and func_3(vs_5839, vp_5839, vvarp_5832, vp_ww, vp_shm, vp_cpo, target_7, target_3)
and func_4(vvarp_5832, target_4)
and func_5(verrmsg_5838, ve_invarg, target_5)
and func_6(vvarp_5832, target_6)
and func_7(vvarp_5832, target_7)
and func_8(verrmsg_5838, ve_invarg, target_8)
and func_9(vgvarp_5841, target_9)
and verrmsg_5838.getType().hasName("char_u *")
and vs_5839.getType().hasName("char_u *")
and vp_5839.getType().hasName("char_u *")
and vgvarp_5841.getType().hasName("char_u **")
and ve_invarg.getType() instanceof ArrayType
and vvarp_5832.getType().hasName("char_u **")
and vp_ww.getType().hasName("char_u *")
and vp_shm.getType().hasName("char_u *")
and vp_cpo.getType().hasName("char_u *")
and verrmsg_5838.getParentScope+() = func
and vs_5839.getParentScope+() = func
and vp_5839.getParentScope+() = func
and vgvarp_5841.getParentScope+() = func
and not ve_invarg.getParentScope+() = func
and vvarp_5832.getParentScope+() = func
and not vp_ww.getParentScope+() = func
and not vp_shm.getParentScope+() = func
and not vp_cpo.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
