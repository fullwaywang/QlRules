/**
 * @name mysql-server-adcd7d4fafc6a8cbefce23e49265eede21466a4f-parse_index_versioned_fields
 * @id cpp/mysql-server/adcd7d4fafc6a8cbefce23e49265eede21466a4f/parseindexversionedfields
 * @description mysql-server-adcd7d4fafc6a8cbefce23e49265eede21466a4f-storage/innobase/mtr/mtr0log.cc-parse_index_versioned_fields mysql-#34173425
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vptr_1015/*, EmptyStmt target_1*/, ExprStmt target_2, Function func) {
exists(IfStmt target_0 |
	exists(EqualityOperation obj_0 | obj_0=target_0.getCondition() |
		obj_0.getLeftOperand().(VariableAccess).getTarget()=vptr_1015
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
	//and target_0.getLocation().isBefore(target_1.getLocation())
	and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getLeftOperand().(VariableAccess).getLocation())
)
}

/*predicate func_1(Function func, EmptyStmt target_1) {
	func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}*/

predicate func_2(Parameter vptr_1015, ExprStmt target_2) {
	exists(AssignExpr obj_0 | obj_0=target_2.getExpr() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getRValue() |
			obj_1.getTarget().hasName("read_2_bytes")
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vptr_1015
			and obj_1.getArgument(1).(VariableAccess).getTarget().getType().hasName("const byte *")
			and obj_1.getArgument(2).(VariableAccess).getTarget().getType().hasName("uint16_t")
		)
		and obj_0.getLValue().(VariableAccess).getTarget()=vptr_1015
	)
}

from Function func, Parameter vptr_1015/*, EmptyStmt target_1*/, ExprStmt target_2
where
not func_0(vptr_1015, target_2, func)
//and func_1(func, target_1)
and func_2(vptr_1015, target_2)
and vptr_1015.getType().hasName("byte *")
and vptr_1015.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
