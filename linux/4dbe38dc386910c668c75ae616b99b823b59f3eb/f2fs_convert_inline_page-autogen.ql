/**
 * @name linux-4dbe38dc386910c668c75ae616b99b823b59f3eb-f2fs_convert_inline_page
 * @id cpp/linux/4dbe38dc386910c668c75ae616b99b823b59f3eb/f2fs_convert_inline_page
 * @description linux-4dbe38dc386910c668c75ae616b99b823b59f3eb-f2fs_convert_inline_page 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vdn_112, Variable vfio_114, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="data_blkaddr"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdn_112
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("set_sbi_flag")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="sbi"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vfio_114
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("f2fs_msg")
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sb"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="sbi"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vfio_114
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%s: corrupted inline inode ino=%lx, i_addr[0]:0x%x, run fsck to fix."
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getType().hasName("const char[25]")
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="i_ino"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="inode"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdn_112
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="data_blkaddr"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdn_112
		and target_0.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(BlockStmt).getStmt(3).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_4(Parameter vdn_112, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("f2fs_put_dnode")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdn_112
		and (func.getEntryPoint().(BlockStmt).getStmt(23)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(23).getFollowingStmt()=target_4))
}

predicate func_6(Parameter vdn_112) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("f2fs_reserve_block")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vdn_112
		and target_6.getArgument(1).(Literal).getValue()="0")
}

predicate func_7(Parameter vdn_112) {
	exists(PointerFieldAccess target_7 |
		target_7.getTarget().getName()="inode"
		and target_7.getQualifier().(VariableAccess).getTarget()=vdn_112)
}

from Function func, Parameter vdn_112, Variable vfio_114
where
not func_0(vdn_112, vfio_114, func)
and not func_4(vdn_112, func)
and vdn_112.getType().hasName("dnode_of_data *")
and func_6(vdn_112)
and func_7(vdn_112)
and vfio_114.getType().hasName("f2fs_io_info")
and vdn_112.getParentScope+() = func
and vfio_114.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
