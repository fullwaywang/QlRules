/**
 * @name unbound-02080f6b180232f43b77f403d0c038e9360a460f-copy_rrset
 * @id cpp/unbound/02080f6b180232f43b77f403d0c038e9360a460f/copy-rrset
 * @description unbound-02080f6b180232f43b77f403d0c038e9360a460f-respip/respip.c-copy_rrset CVE-2019-25038
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdata_464, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_464
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="16776960"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vdata_464, Variable vdsize_465, Variable vi_465, RelationalOperation target_4, ExprStmt target_2, ExprStmt target_3, PostfixIncrExpr target_5) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdsize_465
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="268435455"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="rr_len"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_464
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_465
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(HexLiteral).getValue()="268435455"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_2(Variable vdata_464, Variable vdsize_465, Variable vi_465, ExprStmt target_2) {
		target_2.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vdsize_465
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="rr_len"
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_464
		and target_2.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_465
}

predicate func_3(Variable vdata_464, Variable vdsize_465, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdsize_465
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="56"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_464
		and target_3.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(AddExpr).getValue()="24"
}

predicate func_4(Variable vdata_464, Variable vi_465, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vi_465
		and target_4.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="count"
		and target_4.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_464
}

predicate func_5(Variable vi_465, PostfixIncrExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vi_465
}

from Function func, Variable vdata_464, Variable vdsize_465, Variable vi_465, ExprStmt target_2, ExprStmt target_3, RelationalOperation target_4, PostfixIncrExpr target_5
where
not func_0(vdata_464, target_3, func)
and not func_1(vdata_464, vdsize_465, vi_465, target_4, target_2, target_3, target_5)
and func_2(vdata_464, vdsize_465, vi_465, target_2)
and func_3(vdata_464, vdsize_465, target_3)
and func_4(vdata_464, vi_465, target_4)
and func_5(vi_465, target_5)
and vdata_464.getType().hasName("packed_rrset_data *")
and vdsize_465.getType().hasName("size_t")
and vi_465.getType().hasName("size_t")
and vdata_464.getParentScope+() = func
and vdsize_465.getParentScope+() = func
and vi_465.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
