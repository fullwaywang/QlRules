/**
 * @name linux-d0c7feaf87678371c2c09b3709400be416b2dc62-xfs_agf_verify
 * @id cpp/linux/d0c7feaf87678371c2c09b3709400be416b2dc62/xfs_agf_verify
 * @description linux-d0c7feaf87678371c2c09b3709400be416b2dc62-xfs_agf_verify 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vmp_2840, Variable vagf_2841, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_length"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="sb_dblocks"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="m_sb"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmp_2840
		and target_0.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_0.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_0.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_4(Variable vagf_2841, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_freeblks"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_longest"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_freeblks"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_length"
		and target_4.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_4.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_4.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_4.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_4))
}

predicate func_8(Variable vmp_2840, Variable vagf_2841, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xfs_sb_version_hasrmapbt")
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="m_sb"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmp_2840
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_rmap_blocks"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_length"
		and target_8.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_8.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_8.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_8.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_8))
}

predicate func_12(Variable vmp_2840, Variable vagf_2841, Function func) {
	exists(IfStmt target_12 |
		target_12.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("xfs_sb_version_hasreflink")
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="m_sb"
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmp_2840
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_refcount_blocks"
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("__builtin_bswap32")
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="agf_length"
		and target_12.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vagf_2841
		and target_12.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_12.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_12.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_12))
}

predicate func_16(Variable vmp_2840) {
	exists(FunctionCall target_16 |
		target_16.getTarget().hasName("xfs_agfl_size")
		and target_16.getArgument(0).(VariableAccess).getTarget()=vmp_2840)
}

predicate func_17(Variable vmp_2840) {
	exists(PointerFieldAccess target_17 |
		target_17.getTarget().getName()="m_sb"
		and target_17.getQualifier().(VariableAccess).getTarget()=vmp_2840)
}

predicate func_19(Variable vagf_2841) {
	exists(PointerFieldAccess target_19 |
		target_19.getTarget().getName()="agf_flcount"
		and target_19.getQualifier().(VariableAccess).getTarget()=vagf_2841)
}

predicate func_20(Variable vagf_2841) {
	exists(PointerFieldAccess target_20 |
		target_20.getTarget().getName()="agf_levels"
		and target_20.getQualifier().(VariableAccess).getTarget()=vagf_2841)
}

predicate func_21(Variable vagf_2841) {
	exists(PointerFieldAccess target_21 |
		target_21.getTarget().getName()="agf_length"
		and target_21.getQualifier().(VariableAccess).getTarget()=vagf_2841)
}

from Function func, Variable vmp_2840, Variable vagf_2841
where
not func_0(vmp_2840, vagf_2841, func)
and not func_4(vagf_2841, func)
and not func_8(vmp_2840, vagf_2841, func)
and not func_12(vmp_2840, vagf_2841, func)
and vmp_2840.getType().hasName("xfs_mount *")
and func_16(vmp_2840)
and func_17(vmp_2840)
and vagf_2841.getType().hasName("xfs_agf *")
and func_19(vagf_2841)
and func_20(vagf_2841)
and func_21(vagf_2841)
and vmp_2840.getParentScope+() = func
and vagf_2841.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
