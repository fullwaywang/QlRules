/**
 * @name mysql-server-6eb5af6cc9af8ba4c5cd528cca405b986cd3fb9e-xid_t__operator<
 * @id cpp/mysql-server/6eb5af6cc9af8ba4c5cd528cca405b986cd3fb9e/xidtoperator<
 * @description mysql-server-6eb5af6cc9af8ba4c5cd528cca405b986cd3fb9e-sql/xa.cc-xid_t__operator< mysql-#34918985
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vrhs_135, ReturnStmt target_1, FunctionCall target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getArgument(0) |
		obj_0.getTarget().hasName("get_data")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and exists(FunctionCall obj_1 | obj_1=target_0.getArgument(1) |
		obj_1.getTarget().hasName("get_data")
		and obj_1.getQualifier().(VariableAccess).getTarget()=vrhs_135
	)
	and exists(AddExpr obj_2 | obj_2=target_0.getArgument(2) |
		exists(FunctionCall obj_3 | obj_3=obj_2.getLeftOperand() |
			obj_3.getTarget().hasName("get_gtrid_length")
			and obj_3.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and exists(FunctionCall obj_4 | obj_4=obj_2.getRightOperand() |
			obj_4.getTarget().hasName("get_bqual_length")
			and obj_4.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
	)
	and exists(LTExpr obj_5 | obj_5=target_0.getParent() |
		obj_5.getGreaterOperand().(Literal).getValue()="0"
		and obj_5.getParent().(IfStmt).getThen()=target_1
	)
	and target_0.getTarget().hasName("strncmp")
	and not target_0.getTarget().hasName("memcmp")
}

predicate func_1(RelationalOperation target_2, Function func, ReturnStmt target_1) {
	target_1.getExpr().(Literal).getValue()="1"
	and target_1.getParent().(IfStmt).getCondition()=target_2
	and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, RelationalOperation target_2) {
	 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
	and target_2.getLesserOperand() instanceof FunctionCall
	and target_2.getGreaterOperand().(Literal).getValue()="0"
	and target_2.getEnclosingFunction() = func
}

from Function func, Parameter vrhs_135, FunctionCall target_0, ReturnStmt target_1, RelationalOperation target_2
where
func_0(vrhs_135, target_1, target_0)
and func_1(target_2, func, target_1)
and func_2(func, target_2)
and vrhs_135.getType().hasName("const xid_t &")
and vrhs_135.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
