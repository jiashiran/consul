import RepositoryService from 'consul-ui/services/repository';
import { inject as service } from '@ember/service';

const modelName = 'node';
export default RepositoryService.extend({
  coordinates: service('repository/coordinate'),
  getModelName: function() {
    return modelName;
  },
  findByLeader: function(dc) {
    const query = {
      dc: dc,
    };
    return this.store.queryLeader(this.getModelName(), query);
  },
});
