/**
 * @name openjpeg-6c4e5bacb9d9791fc6ff074bd7958b3820d70514-opj_pi_next_rpcl
 * @id cpp/openjpeg/6c4e5bacb9d9791fc6ff074bd7958b3820d70514/opj-pi-next-rpcl
 * @description openjpeg-6c4e5bacb9d9791fc6ff074bd7958b3820d70514-src/lib/openjp2/pi.c-opj_pi_next_rpcl CVE-2016-9581
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcomp_340, Variable vlevelno_384, LogicalOrExpr target_1, BinaryBitwiseOperation target_2) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="dx"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_340
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlevelno_384
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="dy"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_340
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlevelno_384
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_0.getThen().(BlockStmt).getStmt(0).(ContinueStmt).toString() = "continue;"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vcomp_340, Variable vlevelno_384, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlevelno_384
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="dx"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_340
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlevelno_384
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlevelno_384
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dx"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_340
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getTarget().getName()="dy"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_340
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlevelno_384
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlevelno_384
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="dy"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_340
}

predicate func_2(Variable vcomp_340, Variable vlevelno_384, BinaryBitwiseOperation target_2) {
		target_2.getLeftOperand().(PointerFieldAccess).getTarget().getName()="dx"
		and target_2.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcomp_340
		and target_2.getRightOperand().(VariableAccess).getTarget()=vlevelno_384
}

from Function func, Variable vcomp_340, Variable vlevelno_384, LogicalOrExpr target_1, BinaryBitwiseOperation target_2
where
not func_0(vcomp_340, vlevelno_384, target_1, target_2)
and func_1(vcomp_340, vlevelno_384, target_1)
and func_2(vcomp_340, vlevelno_384, target_2)
and vcomp_340.getType().hasName("opj_pi_comp_t *")
and vlevelno_384.getType().hasName("OPJ_UINT32")
and vcomp_340.getParentScope+() = func
and vlevelno_384.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
