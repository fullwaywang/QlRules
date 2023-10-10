/**
 * @name linux-4dbe38dc386910c668c75ae616b99b823b59f3eb-f2fs_move_inline_dirents
 * @id cpp/linux/4dbe38dc386910c668c75ae616b99b823b59f3eb/f2fs_move_inline_dirents
 * @description linux-4dbe38dc386910c668c75ae616b99b823b59f3eb-f2fs_move_inline_dirents 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdir_346, Variable vpage_349, Variable vdn_350, Variable verr_353, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="data_blkaddr"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdn_350
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("f2fs_put_dnode")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdn_350
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("set_sbi_flag")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("F2FS_P_SB")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_349
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("f2fs_msg")
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sb"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("F2FS_P_SB")
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_349
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s: corrupted inline inode ino=%lx, i_addr[0]:0x%x, run fsck to fix."
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("const char[25]")
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="i_ino"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdir_346
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="data_blkaddr"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdn_350
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_353
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getThen().(BlockStmt).getStmt(4).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0))
}

predicate func_6(Parameter vdir_346, Parameter vipage_346, Variable vdn_350) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("set_new_dnode")
		and target_6.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdn_350
		and target_6.getArgument(1).(VariableAccess).getTarget()=vdir_346
		and target_6.getArgument(2).(VariableAccess).getTarget()=vipage_346
		and target_6.getArgument(3).(Literal).getValue()="0"
		and target_6.getArgument(4).(Literal).getValue()="0")
}

predicate func_7(Parameter vipage_346, Variable vpage_349) {
	exists(NotExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vpage_349
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("f2fs_put_page")
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vipage_346
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_7.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12")
}

predicate func_8(Variable verr_353, Function func) {
	exists(ReturnStmt target_8 |
		target_8.getExpr().(VariableAccess).getTarget()=verr_353
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8)
}

from Function func, Parameter vdir_346, Parameter vipage_346, Variable vpage_349, Variable vdn_350, Variable verr_353
where
not func_0(vdir_346, vpage_349, vdn_350, verr_353, func)
and vdir_346.getType().hasName("inode *")
and func_6(vdir_346, vipage_346, vdn_350)
and vipage_346.getType().hasName("page *")
and vpage_349.getType().hasName("page *")
and func_7(vipage_346, vpage_349)
and vdn_350.getType().hasName("dnode_of_data")
and verr_353.getType().hasName("int")
and func_8(verr_353, func)
and vdir_346.getParentScope+() = func
and vipage_346.getParentScope+() = func
and vpage_349.getParentScope+() = func
and vdn_350.getParentScope+() = func
and verr_353.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
