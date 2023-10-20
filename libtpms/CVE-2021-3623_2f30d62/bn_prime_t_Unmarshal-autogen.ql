/**
 * @name libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-bn_prime_t_Unmarshal
 * @id cpp/libtpms/2f30d620d3c053f20d38b54bf76ac0907821d263/bn-prime-t-Unmarshal
 * @description libtpms-2f30d620d3c053f20d38b54bf76ac0907821d263-src/tpm2/NVMarshal.c-bn_prime_t_Unmarshal CVE-2021-3623
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdata_1504, RelationalOperation target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1504
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignLShiftExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_1504, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="size"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1504
		and target_1.getLesserOperand().(PointerFieldAccess).getTarget().getName()="allocated"
		and target_1.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1504
}

predicate func_2(Parameter vdata_1504, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("TPMLIB_LogPrintfA")
		and target_2.getExpr().(FunctionCall).getArgument(0).(ComplementExpr).getValue()="4294967295"
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="libtpms/tpm2: bn_prime_t: Require size larger %zu than allocated %zu\n"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="size"
		and target_2.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1504
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="allocated"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1504
}

predicate func_3(Parameter vdata_1504, ExprStmt target_3) {
		target_3.getExpr().(AssignLShiftExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="d"
		and target_3.getExpr().(AssignLShiftExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_1504
		and target_3.getExpr().(AssignLShiftExpr).getLValue().(ArrayExpr).getArrayOffset().(DivExpr).getRightOperand().(Literal).getValue()="2"
		and target_3.getExpr().(AssignLShiftExpr).getRValue().(Literal).getValue()="32"
}

from Function func, Parameter vdata_1504, RelationalOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vdata_1504, target_1, target_2, target_3)
and func_1(vdata_1504, target_1)
and func_2(vdata_1504, target_2)
and func_3(vdata_1504, target_3)
and vdata_1504.getType().hasName("bn_prime_t *")
and vdata_1504.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
