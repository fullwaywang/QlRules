/**
 * @name linux-23fcb3340d033d9f081e21e6c12c2db7eaa541d3-xfs_dinode_verify
 * @id cpp/linux/23fcb3340d033d9f081e21e6c12c2db7eaa541d3/xfs-dinode-verify
 * @description linux-23fcb3340d033d9f081e21e6c12c2db7eaa541d3-xfs_dinode_verify 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="32768"
		and not target_0.getValue()="1"
		and target_0.getParent().(EQExpr).getParent().(IfStmt).getCondition() instanceof EqualityOperation
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vmp_379, Parameter vdip_381, Variable vfa_383) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfa_383
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xfs_dinode_verify_fork")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdip_381
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmp_379
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal)
}

predicate func_2(Parameter vmp_379, Parameter vdip_381, Variable vfa_383) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vfa_383
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xfs_dinode_verify_fork")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdip_381
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vmp_379
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_7(Variable vmode_384) {
	exists(BitwiseAndExpr target_7 |
		target_7.getLeftOperand().(VariableAccess).getTarget()=vmode_384
		and target_7.getRightOperand().(Literal).getValue()="61440"
		and target_7.getParent().(EQExpr).getAnOperand() instanceof Literal
		and target_7.getParent().(EQExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_7.getParent().(EQExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_7.getParent().(EQExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here")
}

predicate func_9(Parameter vdip_381) {
	exists(EqualityOperation target_9 |
		target_9.getAnOperand().(PointerFieldAccess).getTarget().getName()="di_forkoff"
		and target_9.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdip_381
		and target_9.getAnOperand().(Literal).getValue()="0")
}

predicate func_10(Parameter vmp_379) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="m_sb"
		and target_10.getQualifier().(VariableAccess).getTarget()=vmp_379)
}

predicate func_11(Parameter vdip_381) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="di_version"
		and target_11.getQualifier().(VariableAccess).getTarget()=vdip_381
		and target_11.getParent().(FunctionCall).getParent().(SubExpr).getRightOperand() instanceof FunctionCall)
}

predicate func_16(Parameter vdip_381) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="di_aformat"
		and target_16.getQualifier().(VariableAccess).getTarget()=vdip_381)
}

predicate func_17(Parameter vdip_381) {
	exists(IfStmt target_17 |
		target_17.getCondition().(PointerFieldAccess).getTarget().getName()="di_anextents"
		and target_17.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdip_381
		and target_17.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_17.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_17.getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here")
}

predicate func_19(Variable vfa_383, Function func) {
	exists(IfStmt target_19 |
		target_19.getCondition().(VariableAccess).getTarget()=vfa_383
		and target_19.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vfa_383
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_19)
}

predicate func_21(Function func) {
	exists(BreakStmt target_21 |
		target_21.toString() = "break;"
		and target_21.getEnclosingFunction() = func)
}

predicate func_22(Function func) {
	exists(SwitchCase target_22 |
		target_22.toString() = "default: "
		and target_22.getEnclosingFunction() = func)
}

predicate func_23(Function func) {
	exists(LabelStmt target_23 |
		target_23.toString() = "label ...:"
		and target_23.getEnclosingFunction() = func)
}

predicate func_26(Function func) {
	exists(Literal target_26 |
		target_26.getValue()="0"
		and target_26.getEnclosingFunction() = func)
}

predicate func_27(Parameter vdip_381, Variable vdi_size_387) {
	exists(SwitchStmt target_27 |
		target_27.getExpr().(PointerFieldAccess).getTarget().getName()="di_format"
		and target_27.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdip_381
		and target_27.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof BitwiseAndExpr
		and target_27.getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_27.getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen() instanceof ReturnStmt
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdi_size_387
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getCondition() instanceof EqualityOperation
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="di_forkoff"
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdip_381
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getThen().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3"
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="sb_inodesize"
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(ValueFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(FunctionCall).getTarget().hasName("xfs_dinode_size")
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof PointerFieldAccess
		and target_27.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen() instanceof ReturnStmt
		and target_27.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="di_nextents"
		and target_27.getStmt().(BlockStmt).getStmt(3).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdip_381
		and target_27.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(LabelStmt).toString() = "label ...:"
		and target_27.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(AsmStmt).toString() = "asm statement"
		and target_27.getStmt().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(LabelLiteral).getValue()="&&__here"
		and target_27.getStmt().(BlockStmt).getStmt(4) instanceof SwitchCase
		and target_27.getStmt().(BlockStmt).getStmt(6) instanceof BreakStmt
		and target_27.getStmt().(BlockStmt).getStmt(7) instanceof SwitchCase
		and target_27.getStmt().(BlockStmt).getStmt(8) instanceof ReturnStmt)
}

predicate func_44(Parameter vmp_379) {
	exists(PointerFieldAccess target_44 |
		target_44.getTarget().getName()="m_rtdev_targp"
		and target_44.getQualifier().(VariableAccess).getTarget()=vmp_379)
}

from Function func, Parameter vmp_379, Parameter vdip_381, Variable vfa_383, Variable vmode_384, Variable vdi_size_387
where
func_0(func)
and not func_1(vmp_379, vdip_381, vfa_383)
and not func_2(vmp_379, vdip_381, vfa_383)
and func_7(vmode_384)
and func_9(vdip_381)
and func_10(vmp_379)
and func_11(vdip_381)
and func_16(vdip_381)
and func_17(vdip_381)
and func_19(vfa_383, func)
and func_21(func)
and func_22(func)
and func_23(func)
and func_26(func)
and func_27(vdip_381, vdi_size_387)
and vmp_379.getType().hasName("xfs_mount *")
and func_44(vmp_379)
and vdip_381.getType().hasName("xfs_dinode *")
and vfa_383.getType().hasName("xfs_failaddr_t")
and vmode_384.getType().hasName("uint16_t")
and vdi_size_387.getType().hasName("uint64_t")
and vmp_379.getParentScope+() = func
and vdip_381.getParentScope+() = func
and vfa_383.getParentScope+() = func
and vmode_384.getParentScope+() = func
and vdi_size_387.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
