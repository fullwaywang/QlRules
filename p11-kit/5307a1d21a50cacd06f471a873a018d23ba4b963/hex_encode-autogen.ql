/**
 * @name p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-hex_encode
 * @id cpp/p11-kit/5307a1d21a50cacd06f471a873a018d23ba4b963/hex-encode
 * @description p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-p11-kit/lists.c-hex_encode CVE-2020-29361
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vn_data_61, AddExpr target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="6148914691236517204"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vn_data_61
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vn_data_61, AddExpr target_1) {
		target_1.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vn_data_61
		and target_1.getAnOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_1.getAnOperand().(Literal).getValue()="1"
}

from Function func, Parameter vn_data_61, AddExpr target_1
where
not func_0(vn_data_61, target_1, func)
and func_1(vn_data_61, target_1)
and vn_data_61.getType().hasName("size_t")
and vn_data_61.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
