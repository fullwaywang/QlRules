/**
 * @name linux-c37e9e013469521d9adb932d17a1795c139b36db-ext4_fill_super
 * @id cpp/linux/c37e9e013469521d9adb932d17a1795c139b36db/ext4_fill_super
 * @description linux-c37e9e013469521d9adb932d17a1795c139b36db-ext4_fill_super CVE-2018-10882
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable ves_3488, Variable vsbi_3489, Parameter vsb_3483) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="s_first_ino"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_3489
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="11"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__ext4_msg")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsb_3483
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="3"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="invalid first ino: %u"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="s_first_ino"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsbi_3489
		and target_0.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="s_rev_level"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ves_3488
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0")
}

predicate func_3(Variable vsbi_3489) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="s_first_ino"
		and target_3.getQualifier().(VariableAccess).getTarget()=vsbi_3489)
}

predicate func_4(Parameter vsb_3483) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="s_blocksize_bits"
		and target_4.getQualifier().(VariableAccess).getTarget()=vsb_3483)
}

from Function func, Variable ves_3488, Variable vsbi_3489, Parameter vsb_3483
where
not func_0(ves_3488, vsbi_3489, vsb_3483)
and ves_3488.getType().hasName("ext4_super_block *")
and vsbi_3489.getType().hasName("ext4_sb_info *")
and func_3(vsbi_3489)
and vsb_3483.getType().hasName("super_block *")
and func_4(vsb_3483)
and ves_3488.getParentScope+() = func
and vsbi_3489.getParentScope+() = func
and vsb_3483.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
